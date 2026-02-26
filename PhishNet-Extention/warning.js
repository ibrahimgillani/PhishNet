// PhishNet Warning Page — threat details display logic
let targetUrl = '';
let verdict = '';
let tabId = null;
let threatData = { threats: [], sources: [], score: 0, confidence: 0 };

// ── Helpers ──
function $(id) { return document.getElementById(id); }

function readQuery() {
    const params = new URLSearchParams(location.search);
    return {
        url: params.get('url'),
        verdict: params.get('verdict'),
        tabId: params.get('tabId') ? Number(params.get('tabId')) : null
    };
}

// ── UI Update Functions ──

function updateVerdict(v) {
    const label = $('verdict-label');
    const title = $('main-title');
    const desc = $('description');

    if (v === 'MALICIOUS') {
        label.textContent = 'MALICIOUS SITE BLOCKED';
        label.className = 'verdict-label malicious';
        title.textContent = 'Dangerous site detected';
        desc.textContent = 'PhishNet\'s multi-source threat intelligence has identified this website as dangerous. Attackers on this site may attempt to steal your passwords, personal information, or install malicious software.';
    } else if (v === 'SUSPICIOUS') {
        document.body.classList.add('suspicious-page');
        label.textContent = 'SUSPICIOUS SITE FLAGGED';
        label.className = 'verdict-label suspicious';
        title.textContent = 'Suspicious site flagged';
        desc.textContent = 'PhishNet has detected suspicious activity associated with this website. While not confirmed as malicious, this site shows characteristics commonly linked to phishing or deceptive practices. Proceed with caution.';
    } else {
        label.textContent = 'WARNING';
        label.className = 'verdict-label suspicious';
        title.textContent = 'Potential threat detected';
        desc.textContent = 'PhishNet has flagged this website for review. Exercise caution before entering any personal information.';
    }
}

function updateUrl(url) {
    const el = $('target-url');
    if (el) el.textContent = url || 'Unknown URL';
}

function updateScore(score) {
    const valueEl = $('score-value');
    const fillEl = $('score-fill');
    if (!valueEl || !fillEl) return;

    const level = score >= 80 ? 'high' : score >= 40 ? 'medium' : 'low';
    valueEl.textContent = `${score}/100`;
    valueEl.className = `score-value ${level}`;
    fillEl.className = `score-fill ${level}`;

    // Animate the bar
    setTimeout(() => {
        fillEl.style.width = `${Math.min(score, 100)}%`;
    }, 100);
}

function updateThreats(threats) {
    const list = $('threats-list');
    if (!list) return;

    if (!threats || threats.length === 0) {
        list.innerHTML = '<div class="no-data">No specific threats identified — flagged based on aggregated risk signals</div>';
        return;
    }

    list.innerHTML = threats.map(t => {
        const typeLabel = formatThreatType(t.type || t.threatType || 'UNKNOWN');
        const source = t.source || 'Unknown';
        let detail = '';

        if (t.detections && t.total) {
            detail = `Detected by ${t.detections} of ${t.total} security engines`;
        } else if (t.confidence) {
            detail = `Confidence: ${t.confidence}`;
        } else if (t.platform) {
            detail = `Platform: ${formatThreatType(t.platform)}`;
        } else if (t.details && typeof t.details === 'string') {
            detail = t.details;
        } else if (t.detail && typeof t.detail === 'string') {
            detail = t.detail;
        } else if (t.tags && t.tags.length) {
            detail = `Tags: ${t.tags.join(', ')}`;
        } else if (t.urlStatus) {
            detail = `URL status: ${t.urlStatus}`;
        } else if (t.count) {
            detail = `${t.count} issues detected`;
        }

        return `
            <div class="threat-item">
                <span class="threat-icon">⚠</span>
                <div class="threat-info">
                    <div class="threat-type">${escapeHtml(typeLabel)}</div>
                    <div class="threat-detail">${escapeHtml(source)}${detail ? ' · ' + escapeHtml(detail) : ''}</div>
                </div>
            </div>
        `;
    }).join('');
}

function updateSources(sources) {
    const list = $('sources-list');
    if (!list) return;

    if (!sources || sources.length === 0) {
        list.innerHTML = '<div class="no-data">No source data available</div>';
        return;
    }

    const items = sources.map(src => {
        if (typeof src === 'string') {
            const isError = src.includes('(error)');
            const name = src.replace(' (error)', '');
            return { name, safe: !isError, isError, detail: '' };
        }
        // Object format from sourceDetails
        const name = src.source || 'Unknown';
        // FIX: Only mark safe if explicitly true — undefined/missing means not safe
        const safe = src.safe === true;
        const details = src.details || {};
        let detail = '';

        if (name.includes('VirusTotal') && details.malicious !== undefined) {
            detail = `${details.malicious}/${details.total} engines flagged`;
        } else if (name.includes('AbuseIPDB') && details.abuseScore !== undefined) {
            detail = `Abuse score: ${details.abuseScore}% \u00b7 ${details.totalReports} reports`;
        } else if (name.includes('Shodan') && details.openPorts !== undefined) {
            detail = `${details.openPorts} open ports \u00b7 ${details.vulns || 0} vulns`;
        } else if (name.includes('ML Model') || name.includes('BERT')) {
            if (details.phishingScore !== undefined) {
                const pct = (details.phishingScore * 100).toFixed(1);
                detail = safe ? `Legitimate (${(100 - details.phishingScore * 100).toFixed(1)}% safe)` : `Phishing confidence: ${pct}%`;
            }
        } else if (name.includes('Heuristics')) {
            const parts = [];
            if (details.typosquattingDetected) parts.push('Typosquatting');
            if (details.structureIssues > 0) parts.push(`${details.structureIssues} structural issues`);
            if (details.note === 'Trusted domain') parts.push('Trusted domain');
            detail = parts.length > 0 ? parts.join(' \u00b7 ') : (safe ? 'No issues' : 'Issues found');        } else if (name.includes('Domain Age')) {
            const ageDays = details.domainAgeDays;
            if (ageDays !== null && ageDays !== undefined) {
                detail = safe ? `Registered ${ageDays} days ago` : `Only ${ageDays} day(s) old`;
            } else {
                detail = details.note || (safe ? 'Established domain' : 'Age unknown');
            }
        } else if (name.includes('Redirect')) {
            const hops = details.totalHops || 0;
            if (hops > 0) {
                const parts = [`${hops} hop(s)`];
                if (details.crossDomainHops > 0) parts.push(`${details.crossDomainHops} cross-domain`);
                if (details.protocolDowngrade) parts.push('HTTPS→HTTP downgrade');
                detail = parts.join(' · ');
            } else {
                detail = safe ? 'No redirects' : (details.note || 'Redirect issues');
            }        }

        return { name, safe, isError: false, detail };
    });

    list.innerHTML = items.map(item => {
        let statusClass, statusText;
        if (item.isError) {
            statusClass = 'error-status';
            statusText = 'Error';
        } else if (item.safe) {
            statusClass = 'safe';
            statusText = 'Clean';
        } else {
            statusClass = 'danger';
            statusText = 'Flagged';
        }

        return `
            <div class="source-row">
                <span class="source-name">${escapeHtml(item.name)}</span>
                ${item.detail ? `<span class="source-detail">${escapeHtml(item.detail)}</span>` : ''}
                <span class="source-status ${statusClass}">${statusText}</span>
            </div>
        `;
    }).join('');
}

function formatThreatType(type) {
    if (!type) return 'Unknown Threat';

    // Human-readable labels for all threat types
    const labels = {
        // SSL / Certificate threats
        'SSL_ANOMALY': 'SSL Certificate Invalid',
        'SELF_SIGNED_CERT': 'Self-Signed Certificate',
        'SSL_EXPIRING': 'SSL Certificate Expiring Soon',
        'CERT_MISMATCH': 'Certificate/Hostname Mismatch',
        'UNTRUSTED_CERT': 'Untrusted Certificate Chain',
        'CERT_NEWLY_ISSUED': 'Newly Issued Certificate',
        'CERT_SHORT_VALIDITY': 'Short Certificate Validity',
        'FREE_CA_NEW_CERT': 'Free CA + New Certificate',
        'WILDCARD_FREE_CA': 'Wildcard from Free CA',
        'WEAK_TLS': 'Weak TLS Version',
        'NO_HTTPS': 'No HTTPS Encryption',
        'CT_NEW_DOMAIN': 'New Domain (CT Logs)',
        'CT_THIN_HISTORY': 'Thin Certificate History',
        // Typosquatting / Impersonation threats
        'TYPOSQUATTING': 'Domain Impersonation Detected',
        'SUSPICIOUS_STRUCTURE': 'Suspicious URL Structure',
        // Domain age threats
        'DOMAIN_VERY_NEW': 'Domain Registered < 7 Days Ago',
        'DOMAIN_NEW': 'Domain Registered < 30 Days Ago',
        'DOMAIN_RECENT': 'Domain Registered < 90 Days Ago',
        // Redirect threats
        'REDIRECT_LOOP': 'Redirect Loop Detected',
        'EXCESSIVE_REDIRECTS': 'Excessive Redirect Chain',
        'CROSS_DOMAIN_REDIRECTS': 'Multiple Cross-Domain Redirects',
        'PROTOCOL_DOWNGRADE': 'HTTPS → HTTP Protocol Downgrade',
    };
    if (labels[type]) return labels[type];

    return type
        .replace(/_/g, ' ')
        .replace(/\b\w/g, c => c.toUpperCase())
        .replace('Malicious', 'Malicious Detection')
        .replace('Social Engineering', 'Phishing / Social Engineering');
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text || '';
    return div.innerHTML;
}

// ── Details Toggle ──
function setupDetailsToggle() {
    const toggle = $('details-toggle');
    const panel = $('details-panel');
    const toggleText = $('toggle-text');
    if (!toggle || !panel) return;

    toggle.addEventListener('click', () => {
        const isOpen = panel.classList.toggle('visible');
        toggle.classList.toggle('open', isOpen);
        if (toggleText) toggleText.textContent = isOpen ? 'Hide threat details' : 'Show threat details';
    });
}

// ── Button Actions ──
function disableButtons() {
    document.querySelectorAll('.btn').forEach(btn => {
        btn.disabled = true;
        btn.style.opacity = '0.7';
        btn.style.cursor = 'not-allowed';
    });
}

function sendDecision(decision) {
    if (!targetUrl) return;
    const statusEl = $('status-text');

    chrome.runtime.sendMessage(
        { type: 'warning-decision', decision, url: targetUrl, tabId },
        () => {
            if (decision === 'stay_safe') {
                if (statusEl) statusEl.textContent = '✓ Navigation blocked. Going back...';
                disableButtons();
            }
        }
    );
}

// ── Data Hydration ──
function hydrateUI(data) {
    if (data.url) {
        targetUrl = data.url;
        updateUrl(targetUrl);
    }
    if (data.verdict) {
        verdict = data.verdict;
        updateVerdict(verdict);
    }
    if (data.tabId !== undefined && data.tabId !== null) {
        tabId = data.tabId;
    }
    if (data.score !== undefined) {
        updateScore(data.score);
    }
    if (data.threats) {
        updateThreats(data.threats);
    }
    if (data.sources) {
        updateSources(data.sources);
    }
}

function hydrateFromBackground() {
    chrome.runtime.sendMessage({ type: 'warning-page-ready', tabId }, (res) => {
        if (res) {
            hydrateUI(res);
        }
    });
}

// ── Init ──
document.addEventListener('DOMContentLoaded', () => {
    // Immediate init from URL params
    const initial = readQuery();
    targetUrl = initial.url || '';
    verdict = initial.verdict || '';
    tabId = initial.tabId;
    updateUrl(targetUrl);
    updateVerdict(verdict);

    // Fetch full threat data from background
    hydrateFromBackground();

    // Setup interactions
    setupDetailsToggle();

    const continueBtn = $('continue-btn');
    const staySafeBtn = $('stay-safe-btn');
    if (continueBtn) continueBtn.addEventListener('click', () => sendDecision('continue'));
    if (staySafeBtn) staySafeBtn.addEventListener('click', () => sendDecision('stay_safe'));
});
