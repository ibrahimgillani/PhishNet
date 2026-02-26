// Background service worker for Safe Browsing navigation checks
try { importScripts('url-prefilter.js'); } catch (e) { console.warn('[PhishNet] Pre-filter module not loaded:', e.message); }
const PROTECTION_STORAGE_KEY = 'phishnetProtectionState';
const SCAN_HISTORY_KEY = 'phishnetScanHistory';
const MAX_SCAN_HISTORY = 50; // Keep last 50 scans
const SCAN_ENDPOINT = 'http://localhost:5000/api/v1/urls/scan';
const SCAN_TIMEOUT_MS = 30000; // 30s — multi-source scan checks 7 APIs (GSB, VT, URLhaus, AbuseIPDB, Shodan, ML, Heuristics)
const SCAN_CACHE_TTL_MS = 300000; // 5 minutes
const RESCAN_GRACE_MS = 10000;    // don't re-scan the same URL within 10 s
const RESCAN_MAX_PER_URL = 3;     // max re-scans per URL per cache lifetime

let protectionState = { isProtected: false, alwaysOn: false };
const allowOnceByTab = new Map();
const pendingWarningByTab = new Map();
// Enhanced cache: url -> { status, timestamp, threats, sources, score, confidence, contentHash, rescanCount }
const scanCache = new Map();

init();

function init() {
    chrome.storage.local.get([PROTECTION_STORAGE_KEY], (res) => {
        applyProtectionState(res?.[PROTECTION_STORAGE_KEY]);
    });

    chrome.storage.onChanged.addListener((changes, areaName) => {
        if (areaName !== 'local') return;
        if (changes[PROTECTION_STORAGE_KEY]) {
            applyProtectionState(changes[PROTECTION_STORAGE_KEY].newValue);
        }
    });

    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
        // Token sync from content script (bridges website localStorage -> chrome.storage.local)
        if (message?.type === 'phishnet.sync-token') {
            if (message.token) {
                chrome.storage.local.set({ accessToken: message.token }, () => {
                    console.log('[PhishNet] Auth token synced from website');
                    // Also try to auto-fetch user profile and set extension login state
                    autoLoginFromToken(message.token);
                    sendResponse?.({ ok: true });
                });
            } else {
                chrome.storage.local.remove(['accessToken', 'refreshToken'], () => {
                    console.log('[PhishNet] Auth token cleared (website logout)');
                    sendResponse?.({ ok: true });
                });
            }
            return true; // Keep message channel open for async response
        }

        if (message?.type === 'phishnet.protection-state') {
            applyProtectionState(message.payload);
            sendResponse?.({ ok: true });
            return;
        }

        // ── Content hash: store/verify page fingerprint ──
        if (message?.type === 'phishnet.content-hash') {
            const cached = scanCache.get(message.url);
            if (cached) {
                if (!cached.contentHash) {
                    // First hash for this cache entry — store it
                    cached.contentHash = message.hash;
                } else if (cached.contentHash !== message.hash) {
                    // Hash mismatch — page content changed since last scan
                    console.log('[PhishNet] Content hash mismatch for cached entry:',
                        message.url, cached.contentHash, '→', message.hash);
                    scanCache.delete(message.url);
                    triggerRescan(message.url, sender?.tab?.id, 'content-hash-mismatch');
                }
            }
            sendResponse?.({ ok: true });
            return;
        }

        // ── Content changed: DOM mutations altered the page fingerprint ──
        if (message?.type === 'phishnet.content-changed') {
            console.log('[PhishNet] DOM content changed:', message.url,
                '(', message.oldHash, '→', message.newHash, ')');
            scanCache.delete(message.url);
            triggerRescan(message.url, sender?.tab?.id, 'dom-mutation');
            sendResponse?.({ ok: true });
            return;
        }

        // ── Form submission: credential forms trigger re-scan ──
        if (message?.type === 'phishnet.form-submit') {
            console.log('[PhishNet] Form submit on:', message.url,
                '→', message.actionUrl,
                'credentials:', message.hasCredentials,
                'method:', message.method);
            if (message.hasCredentials) {
                // Credential form — invalidate both page and action URL caches
                scanCache.delete(message.url);
                if (message.actionUrl && message.actionUrl !== message.url) {
                    scanCache.delete(message.actionUrl);
                }
                triggerRescan(message.url, sender?.tab?.id, 'credential-submit');
            }
            sendResponse?.({ ok: true });
            return;
        }

        // ── Meta-refresh redirect detected by page-monitor.js ──
        if (message?.type === 'phishnet.meta-redirect') {
            console.log('[PhishNet] Meta refresh redirect:', message.sourceUrl, '→', message.targetUrl);
            scanCache.delete(message.targetUrl);
            triggerRescan(message.targetUrl, sender?.tab?.id, 'meta-redirect');
            sendResponse?.({ ok: true });
            return;
        }

        // ── SPA navigation (pushState/replaceState/hashchange) ──
        if (message?.type === 'phishnet.spa-navigation') {
            const targetUrl = message.targetUrl;
            if (targetUrl && !shouldIgnoreUrl(targetUrl)) {
                const cached = scanCache.get(targetUrl);
                if (!cached || Date.now() - cached.timestamp >= SCAN_CACHE_TTL_MS) {
                    console.log('[PhishNet] SPA navigation, scanning:', targetUrl, 'via', message.method);
                    triggerRescan(targetUrl, sender?.tab?.id, 'spa-' + message.method);
                }
            }
            sendResponse?.({ ok: true });
            return;
        }

        // ── Email Scan: full header + body analysis ──
        if (message?.type === 'phishnet.email-scan') {
            const payload = message.payload;
            console.log('[PhishNet] Email scan request from', payload?.platform, '| sender:', payload?.sender);
            (async () => {
                try {
                    const token = await getAccessToken();
                    const headers = { 'Content-Type': 'application/json' };
                    if (token) headers['Authorization'] = `Bearer ${token}`;

                    const resp = await fetch('http://localhost:5000/api/v1/emails/scan', {
                        method: 'POST',
                        headers,
                        body: JSON.stringify({
                            headers: payload.headers,
                            subject: payload.subject,
                            body: payload.body,
                            rawEmail: payload.rawEmail || null
                        })
                    });

                    if (!resp.ok) {
                        const errText = await resp.text();
                        console.warn('[PhishNet] Email scan HTTP error:', resp.status, errText);
                        sendResponse({ success: false, error: `Server error: ${resp.status}` });
                        return;
                    }

                    const data = await resp.json();
                    console.log('[PhishNet] Email scan result:', data.verdict, '| score:', data.score);

                    // Save to scan history
                    await saveScanResult({
                        url: `email://${payload.sender || 'unknown'}`,
                        result: data.verdict || 'SAFE',
                        threats: [
                            ...(data.headerAnalysis?.findings?.filter(f => f.severity === 'high' || f.severity === 'critical') || []),
                            ...(data.bodyAnalysis?.findings?.filter(f => f.severity === 'high' || f.severity === 'critical') || [])
                        ],
                        timestamp: Date.now(),
                        scanType: 'email',
                        sender: payload.sender,
                        subject: payload.subject,
                        platform: payload.platform
                    });

                    sendResponse({ success: true, data });
                } catch (err) {
                    console.error('[PhishNet] Email scan failed:', err);
                    sendResponse({ success: false, error: err.message });
                }
            })();
            return true; // Keep message channel open for async response
        }

        if (message?.type === 'warning-page-ready') {
            const tabId = sender?.tab?.id ?? message.tabId;
            const pending = tabId ? pendingWarningByTab.get(tabId) : null;
            sendResponse?.({
                url: pending?.url || null,
                verdict: pending?.verdict || null,
                tabId: tabId || null,
                threats: pending?.threats || [],
                sources: pending?.sources || [],
                score: pending?.score || 0,
                confidence: pending?.confidence || 0
            });
            return;
        }

        if (message?.type === 'warning-decision') {
            const tabId = sender?.tab?.id ?? message.tabId;
            if (!tabId) {
                sendResponse?.({ ok: false, reason: 'missing-tab' });
                return;
            }

            const { decision, url } = message;
            pendingWarningByTab.delete(tabId);

            if (decision === 'continue' && url) {
                allowOnceByTab.set(tabId, url);
                chrome.tabs.update(tabId, { url });
            }

            if (decision === 'stay_safe') {
                // Go back in browser history using Chrome API
                chrome.tabs.goBack(tabId);
            }

            sendResponse?.({ ok: true });
            return true;
        }
    });

    chrome.webNavigation.onBeforeNavigate.addListener(handleNavigation);

    // ── Server/client redirect detection ──
    chrome.webNavigation.onCommitted.addListener((details) => {
        if (!protectionState.isProtected) return;
        if (details.frameId !== 0) return;
        const qualifiers = details.transitionQualifiers || [];
        const isRedirect = qualifiers.includes('server_redirect') ||
                           qualifiers.includes('client_redirect');
        if (isRedirect) {
            const url = details.url;
            if (shouldIgnoreUrl(url)) return;
            console.log('[PhishNet] Redirect committed:', url, 'qualifiers:', qualifiers);
            scanCache.delete(url);
            triggerRescan(url, details.tabId, 'redirect-' + qualifiers.join('+'));
        }
    });
}

function applyProtectionState(payload) {
    if (!payload || typeof payload !== 'object') return;
    protectionState.isProtected = !!payload.isProtected;
    protectionState.alwaysOn = !!payload.alwaysOn;
}

// ════════════════════════════════════════════════════════════════
//  Re-scan: triggered by cache invalidation signals
//  Guards: grace period, max re-scans per URL, ignore-list
// ════════════════════════════════════════════════════════════════
async function triggerRescan(url, tabId, reason) {
    if (!url || shouldIgnoreUrl(url)) return;

    // Grace period — don't re-scan if we just scanned
    const existing = scanCache.get(url);
    if (existing && Date.now() - existing.timestamp < RESCAN_GRACE_MS) {
        console.log('[PhishNet] Re-scan skipped (grace period):', url);
        return;
    }

    // Limit re-scans to prevent infinite loops
    const count = (existing?.rescanCount || 0);
    if (count >= RESCAN_MAX_PER_URL) {
        console.log('[PhishNet] Re-scan skipped (max re-scans reached):', url);
        return;
    }

    console.log('[PhishNet] Re-scanning:', url, '| reason:', reason, '| attempt:', count + 1);

    const keepAlive = setInterval(() => chrome.runtime.getPlatformInfo(() => {}), 20000);
    try {
        const verdict = await scanUrl(url);
        const status = verdict?.status || 'SAFE';

        scanCache.set(url, {
            status,
            timestamp: Date.now(),
            threats: verdict?.threats || [],
            sources: verdict?.sourceDetails || verdict?.sources || [],
            score: verdict?.score || 0,
            confidence: verdict?.confidence || 0,
            contentHash: null,       // will be populated by next page-monitor hash
            rescanCount: count + 1,
            rescanReason: reason
        });

        console.log('[PhishNet] Re-scan result:', status, '| score:', verdict?.score, '| reason:', reason);

        // Save to scan history
        await saveScanResult({
            url,
            result: status,
            threats: verdict?.threats || [],
            timestamp: Date.now(),
            rescanReason: reason
        });

        // If the re-scan found threats, show warning immediately
        if (status !== 'SAFE' && tabId) {
            pendingWarningByTab.set(tabId, {
                url,
                verdict: status,
                threats: verdict?.threats || [],
                sources: verdict?.sourceDetails || verdict?.sources || [],
                score: verdict?.score || 0,
                confidence: verdict?.confidence || 0
            });
            const warningUrl = buildWarningPageUrl(url, status, tabId);
            console.log('[PhishNet] Re-scan triggered warning for:', url);
            chrome.tabs.update(tabId, { url: warningUrl });
        }
    } catch (err) {
        console.warn('[PhishNet] Re-scan failed for', url, ':', err?.message || err);
    } finally {
        clearInterval(keepAlive);
    }
}

async function handleNavigation(details) {
    try {
        if (!protectionState.isProtected) return;
        if (details.frameId !== 0) return;
        const targetUrl = details.url || '';
        if (shouldIgnoreUrl(targetUrl)) return;

        const allowKey = allowOnceByTab.get(details.tabId);
        if (allowKey && allowKey === targetUrl) {
            console.log('[PhishNet] Allowed once for:', targetUrl);
            allowOnceByTab.delete(details.tabId);
            return;
        }

        const existing = pendingWarningByTab.get(details.tabId);
        if (existing && existing.url === targetUrl) {
            console.log('[PhishNet] Warning already pending for:', targetUrl);
            return;
        }

        // Check cache first
        const cached = scanCache.get(targetUrl);
        if (cached && Date.now() - cached.timestamp < SCAN_CACHE_TTL_MS) {
            console.log('[PhishNet] Cache hit for:', targetUrl, '→', cached.status);
            if (cached.status === 'SAFE') return;
            pendingWarningByTab.set(details.tabId, { url: targetUrl, verdict: cached.status, threats: cached.threats || [], sources: cached.sources || [], score: cached.score || 0, confidence: cached.confidence || 0 });
            const warningUrl = buildWarningPageUrl(targetUrl, cached.status, details.tabId);
            chrome.tabs.update(details.tabId, { url: warningUrl });
            return;
        }

        console.log('[PhishNet] Scanning:', targetUrl);
        // Keep the service worker alive during scan (MV3 can kill idle workers)
        const keepAlive = setInterval(() => chrome.runtime.getPlatformInfo(() => {}), 20000);
        let verdict;
        try {
            verdict = await scanUrl(targetUrl);
        } finally {
            clearInterval(keepAlive);
        }
        const status = verdict?.status || 'SAFE';
        
        // Cache result (include full threat data for warning page)
        scanCache.set(targetUrl, {
            status,
            timestamp: Date.now(),
            threats: verdict?.threats || [],
            sources: verdict?.sourceDetails || verdict?.sources || [],
            score: verdict?.score || 0,
            confidence: verdict?.confidence || 0,
            contentHash: null,    // populated by page-monitor.js after load
            rescanCount: 0
        });
        console.log('[PhishNet] Scan result:', status);
        
        // Save to scan history for security insights
        await saveScanResult({
            url: targetUrl,
            result: status,
            threats: verdict?.threats || [],
            timestamp: Date.now()
        });
        
        if (status === 'SAFE') return;

        pendingWarningByTab.set(details.tabId, { url: targetUrl, verdict: status, threats: verdict?.threats || [], sources: verdict?.sourceDetails || verdict?.sources || [], score: verdict?.score || 0, confidence: verdict?.confidence || 0 });
        const warningUrl = buildWarningPageUrl(targetUrl, status, details.tabId);
        console.log('[PhishNet] Redirecting to warning page:', warningUrl);
        chrome.tabs.update(details.tabId, { url: warningUrl });
    } catch (err) {
        console.warn('[PhishNet] Navigation scan failed (allowing safe passage):', err);
        // On scan error, allow navigation to proceed (don't block)
    }
}

function shouldIgnoreUrl(url) {
    try {
        const parsed = new URL(url);
        if (parsed.protocol === 'chrome:' || parsed.protocol === 'edge:' || parsed.protocol === 'about:') return true;
        if (parsed.protocol === 'chrome-extension:') return true;
        // Skip local files — they can't be phishing
        if (parsed.protocol === 'file:') return true;
        // Skip localhost, 127.x.x.x, [::1], and private/reserved IPs
        const host = parsed.hostname;
        if (host === 'localhost' || host === '[::1]') return true;
        if (/^127\./.test(host)) return true;
        if (/^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)/.test(host)) return true;
        if (host === '0.0.0.0') return true;
        return false;
    } catch (e) {
        return true;
    }
}

async function scanUrl(url) {
    // ── On-Device Pre-Filter: instant block for obvious phishing ──
    if (typeof preFilterUrl === 'function') {
        try {
            const pf = preFilterUrl(url);
            if (pf.action === 'BLOCK') {
                console.log('[PhishNet] ⚡ PRE-FILTER BLOCK:', url, '→', pf.reason);
                return {
                    status: pf.status || 'MALICIOUS',
                    score: pf.score,
                    confidence: pf.score,
                    threats: pf.flags.map(f => ({ source: 'Pre-Filter', type: f.type, detail: f.detail })),
                    sources: ['On-Device Pre-Filter'],
                    sourceDetails: [{ source: 'On-Device Pre-Filter', safe: false, details: { flags: pf.flags } }],
                    explanation: pf.explanation,
                    preFiltered: true,
                    earlyExit: pf.reason
                };
            }
            if (pf.flags && pf.flags.length > 0) {
                console.log('[PhishNet] Pre-filter hints for', url, ':', pf.flags.map(f => f.type).join(', '));
            }
        } catch (pfErr) {
            console.warn('[PhishNet] Pre-filter error (continuing to backend):', pfErr.message);
        }
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => {
        controller.abort(new DOMException('Scan timed out after ' + SCAN_TIMEOUT_MS + 'ms', 'TimeoutError'));
    }, SCAN_TIMEOUT_MS);

    try {
        const headers = { 'Content-Type': 'application/json' };
        const token = await getAccessToken();
        if (token) {
            headers['Authorization'] = `Bearer ${token}`;
            console.log('[PhishNet] Auth token attached to scan request');
        } else {
            console.warn('[PhishNet] No auth token available — scan will NOT be saved to DB. Log in on the website or extension popup.');
        }

        console.log('[PhishNet] Calling scan endpoint for:', url);
        const resp = await fetch(SCAN_ENDPOINT, {
            method: 'POST',
            headers,
            body: JSON.stringify({ url }),
            signal: controller.signal
        });

        if (!resp.ok) {
            console.warn('[PhishNet] Scan returned status:', resp.status);
            throw new Error(`Scan failed: ${resp.status}`);
        }
        
        const data = await resp.json();
        console.log('[PhishNet] Scan response:', data);
        return data;
    } catch (err) {
        const isTimeout = err?.name === 'TimeoutError' || err?.name === 'AbortError';
        if (isTimeout) {
            console.warn('[PhishNet] Scan timed out for:', url, '— allowing navigation');
        } else {
            console.error('[PhishNet] Scan error:', err?.message || err);
        }
        // Return safe status on error (fail open, don't block user)
        return { status: 'SAFE', threats: [] };
    } finally {
        clearTimeout(timeout);
    }
}

async function getAccessToken() {
    // 1. Try chrome.storage.local (fastest — set by content script sync or popup login)
    const stored = await new Promise((resolve) => {
        chrome.storage.local.get(['accessToken'], (result) => {
            resolve(result?.accessToken || null);
        });
    });
    if (stored) return stored;

    // 2. No token in storage — try to fetch from an open PhishNet localhost tab
    console.log('[PhishNet] No stored token, attempting to fetch from localhost tabs...');
    try {
        const tabs = await chrome.tabs.query({ url: ['http://localhost/*', 'http://127.0.0.1/*'] });
        for (const tab of tabs) {
            if (!tab.id) continue;
            try {
                // Ask content script on that tab for the token
                const response = await chrome.tabs.sendMessage(tab.id, { type: 'phishnet.request-token' });
                if (response?.token) {
                    console.log('[PhishNet] Token retrieved from content script on tab', tab.id);
                    // Cache it in chrome.storage.local for future scans
                    await new Promise(r => chrome.storage.local.set({ accessToken: response.token }, r));
                    return response.token;
                }
            } catch (e) {
                // Content script may not be injected on this tab — try next
            }
        }
    } catch (e) {
        console.log('[PhishNet] Tab query failed:', e.message);
    }

    // 3. Last resort — use chrome.scripting.executeScript to read localStorage directly
    try {
        const tabs = await chrome.tabs.query({ url: ['http://localhost/*', 'http://127.0.0.1/*'] });
        for (const tab of tabs) {
            if (!tab.id) continue;
            try {
                const results = await chrome.scripting.executeScript({
                    target: { tabId: tab.id },
                    func: () => localStorage.getItem('token')
                });
                const token = results?.[0]?.result;
                if (token) {
                    console.log('[PhishNet] Token retrieved via scripting API from tab', tab.id);
                    await new Promise(r => chrome.storage.local.set({ accessToken: token }, r));
                    return token;
                }
            } catch (e) {
                // This tab may not allow scripting — try next
            }
        }
    } catch (e) {
        console.log('[PhishNet] Scripting fallback failed:', e.message);
    }

    return null;
}

function buildWarningPageUrl(url, verdict, tabId) {
    const base = chrome.runtime.getURL('warning.html');
    const params = new URLSearchParams();
    params.set('url', url);
    params.set('verdict', verdict);
    if (tabId !== undefined && tabId !== null) params.set('tabId', tabId);
    return `${base}?${params.toString()}`;
}

// Auto-login: when a website token is synced, fetch user profile and persist login state
// so the popup shows the user as logged in without requiring a separate popup login
async function autoLoginFromToken(token) {
    try {
        const resp = await fetch('http://localhost:5000/api/v1/users/profile', {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        if (!resp.ok) return;
        const data = await resp.json();
        if (data.success && data.data) {
            const user = data.data;
            const fullName = (user.firstName && user.lastName)
                ? `${user.firstName} ${user.lastName}` : (user.name || 'User');
            // Save synced user data so popup can auto-login on next open
            const syncedUser = {
                name: fullName,
                email: user.email,
                userId: user._id,
                firstName: user.firstName,
                lastName: user.lastName,
                syncedAt: Date.now()
            };
            await chrome.storage.local.set({ phishNetSyncedUser: syncedUser });
            console.log('[PhishNet] Auto-login from website token for:', user.email);
        }
    } catch (e) {
        console.log('[PhishNet] Auto-login failed (non-fatal):', e.message);
    }
}

async function saveScanResult(result) {
    return new Promise((resolve) => {
        chrome.storage.local.get([SCAN_HISTORY_KEY], (res) => {
            let history = res?.[SCAN_HISTORY_KEY] || [];
            if (!Array.isArray(history)) history = [];
            
            // Add new result to the top
            history.unshift(result);
            
            // Keep only last MAX_SCAN_HISTORY items
            if (history.length > MAX_SCAN_HISTORY) {
                history = history.slice(0, MAX_SCAN_HISTORY);
            }
            
            chrome.storage.local.set({ [SCAN_HISTORY_KEY]: history }, () => {
                console.log('[PhishNet] Saved scan result. Total history:', history.length);
                resolve();
            });
        });
    });
}
