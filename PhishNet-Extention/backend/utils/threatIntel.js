/**
 * PhishNet Multi-Source Threat Intelligence Scanner
 * 
 * Checks URLs against multiple threat intelligence APIs in parallel:
 * 1. Google Safe Browsing  - Known malware/phishing/social engineering
 * 2. VirusTotal            - 90+ antivirus engine checks
 * 3. URLhaus (abuse.ch)    - Known malware distribution URLs
 * 4. AbuseIPDB             - IP abuse reputation
 * 5. Shodan                - IP/host intelligence & reputation
 * 6. ML Model (BERT)       - Zero-day AI phishing classifier
 * 7. URL Heuristics        - Typosquatting, SSL, structure analysis
 * 8. RDAP Domain Age       - Domain registration age (new domains = suspicious)
 * 9. Redirect Chain        - Follow redirects and scan final destination
 * 
 * All checks run in parallel with individual timeouts.
 * A combined verdict is produced from all responses.
 */

const axios = require('axios');
const dns = require('dns');
const https = require('https');
const http = require('http');
const { promisify } = require('util');

const dnsResolve = promisify(dns.resolve4);

// ── New modules ──
let headlessBrowser = null;
try { headlessBrowser = require('./headlessBrowser'); } catch (_) { /* optional */ }
let feedbackModule = null;
try { feedbackModule = require('./userFeedback'); } catch (_) { /* optional */ }

const API_TIMEOUT = 8000; // 8s per API
const HF_TIMEOUT  = 15000; // 15s — HF models have cold-start latency
const RDAP_TIMEOUT = 6000; // 6s for RDAP lookup
const REDIRECT_TIMEOUT = 8000; // 8s to follow redirect chain

// ─────────────────────────────────────────────
// 1. GOOGLE SAFE BROWSING
// ─────────────────────────────────────────────
async function checkGoogleSafeBrowsing(url, apiKey) {
  if (!apiKey) return null;
  const endpoint = 'https://safebrowsing.googleapis.com/v4/threatMatches:find';
  const payload = {
    client: { clientId: 'phishnet-extension', clientVersion: '1.0.1' },
    threatInfo: {
      threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
      platformTypes: ['ANY_PLATFORM'],
      threatEntryTypes: ['URL'],
      threatEntries: [{ url }]
    }
  };

  try {
    const { data } = await axios.post(`${endpoint}?key=${apiKey}`, payload, { timeout: API_TIMEOUT });
    const matches = Array.isArray(data?.matches) ? data.matches : [];
    const threats = matches.map(m => ({
      source: 'Google Safe Browsing',
      type: (m.threatType || 'UNKNOWN').toUpperCase(),
      platform: (m.platformType || 'ANY_PLATFORM').toUpperCase()
    }));

    return {
      source: 'Google Safe Browsing',
      safe: threats.length === 0,
      threats,
      raw: data
    };
  } catch (err) {
    const status = err.response?.status;
    // 400/401/403 = invalid/disabled/revoked API key — skip silently
    if (status === 400 || status === 401 || status === 403) {
      console.warn(`[ThreatIntel] Google Safe Browsing API key error (HTTP ${status}) — skipping source`);
      return null;
    }
    // Other errors (timeout, network, 5xx) — re-throw so caller records the error
    throw err;
  }
}

// ─────────────────────────────────────────────
// 2. VIRUSTOTAL  (free tier: 4 req/min, 500/day)
// ─────────────────────────────────────────────

// In-memory cache: URL → { result, ts }  (TTL = 10 minutes)
const _vtCache = new Map();
const VT_CACHE_TTL = 10 * 60 * 1000; // 10 min

async function checkVirusTotal(url, apiKey) {
  if (!apiKey) return null;

  // NOTE: No trusted-domain fast-path — all URLs are evaluated by VirusTotal.
  // Trusted-domain risk reduction is applied at the scoring layer, not per-source.

  // ── Cache check ──
  const cached = _vtCache.get(url);
  if (cached && (Date.now() - cached.ts) < VT_CACHE_TTL) {
    return { ...cached.result, note: 'Cached result' };
  }

  // ── Step 1: Try to GET existing report first (1 API call instead of 2) ──
  const urlId = Buffer.from(url).toString('base64').replace(/=+$/, '');
  let stats = null;

  try {
    const reportResp = await axios.get(
      `https://www.virustotal.com/api/v3/urls/${urlId}`,
      { headers: { 'x-apikey': apiKey }, timeout: API_TIMEOUT }
    );
    stats = reportResp.data?.data?.attributes?.last_analysis_stats || {};
  } catch (err) {
    // 404 = never scanned → need to submit; 429 = rate limited → retry
    if (err.response?.status === 429) {
      // Wait 16 seconds (VT resets per-minute window) and retry once
      await new Promise(r => setTimeout(r, 16000));
      try {
        const retry = await axios.get(
          `https://www.virustotal.com/api/v3/urls/${urlId}`,
          { headers: { 'x-apikey': apiKey }, timeout: API_TIMEOUT }
        );
        stats = retry.data?.data?.attributes?.last_analysis_stats || {};
      } catch (retryErr) {
        throw retryErr; // give up after 1 retry
      }
    } else if (err.response?.status === 404) {
      // Not yet in VT database — submit it
      try {
        await axios.post(
          'https://www.virustotal.com/api/v3/urls',
          new URLSearchParams({ url }).toString(),
          {
            headers: { 'x-apikey': apiKey, 'Content-Type': 'application/x-www-form-urlencoded' },
            timeout: API_TIMEOUT
          }
        );
        // Wait for analysis then fetch
        await new Promise(r => setTimeout(r, 3000));
        const afterSubmit = await axios.get(
          `https://www.virustotal.com/api/v3/urls/${urlId}`,
          { headers: { 'x-apikey': apiKey }, timeout: API_TIMEOUT }
        );
        stats = afterSubmit.data?.data?.attributes?.last_analysis_stats || {};
      } catch (submitErr) {
        // If submit also 429, throw so it shows as error
        throw submitErr;
      }
    } else {
      throw err;
    }
  }

  if (!stats) stats = {};
  const malicious = stats.malicious || 0;
  const suspicious = stats.suspicious || 0;
  const harmless = stats.harmless || 0;
  const undetected = stats.undetected || 0;
  const total = malicious + suspicious + harmless + undetected;

  const threats = [];
  if (malicious > 0) {
    threats.push({ source: 'VirusTotal', type: 'MALICIOUS', detections: malicious, total });
  }
  if (suspicious > 0) {
    threats.push({ source: 'VirusTotal', type: 'SUSPICIOUS', detections: suspicious, total });
  }

  const result = {
    source: 'VirusTotal',
    safe: malicious === 0 && suspicious === 0,
    malicious, suspicious, total, threats, raw: stats
  };

  // Cache the result
  _vtCache.set(url, { result, ts: Date.now() });

  return result;
}

// ─────────────────────────────────────────────
// 3. URLHAUS (abuse.ch) — Free public API (auth key optional but recommended)
// ─────────────────────────────────────────────
async function checkURLhaus(url, authKey) {
  const headers = { 'Content-Type': 'application/x-www-form-urlencoded' };
  // URLhaus now requires Auth-Key header; if not available, try without it
  if (authKey && authKey !== 'free-public-api') {
    headers['Auth-Key'] = authKey;
  }

  const { data } = await axios.post(
    'https://urlhaus-api.abuse.ch/v1/url/',
    new URLSearchParams({ url }).toString(),
    { headers, timeout: API_TIMEOUT }
  );

  // query_status: "no_results" = clean, "ok" = found in database (malicious)
  const found = data?.query_status === 'ok';
  const threats = [];
  if (found) {
    threats.push({
      source: 'URLhaus',
      type: (data.threat || 'MALWARE_DISTRIBUTION').toUpperCase(),
      tags: data.tags || [],
      urlStatus: data.url_status || 'unknown'
    });
  }

  return {
    source: 'URLhaus',
    safe: !found,
    threats,
    raw: data
  };
}

// ─────────────────────────────────────────────
// 4. ABUSEIPDB — Check IP abuse reports
// ─────────────────────────────────────────────
async function checkAbuseIPDB(hostname, apiKey) {
  if (!apiKey) return null;

  // NOTE: No trusted-domain fast-path — all URLs evaluated.
  // Trusted-domain risk reduction is applied at the scoring layer.

  // Resolve hostname to IP first
  let ip;
  try {
    const ips = await dnsResolve(hostname);
    ip = ips[0];
  } catch (e) {
    return { source: 'AbuseIPDB', safe: true, threats: [], note: 'DNS resolution failed' };
  }

  const { data } = await axios.get(
    `https://api.abuseipdb.com/api/v2/check`,
    {
      params: { ipAddress: ip, maxAgeInDays: 90, verbose: '' },
      headers: {
        'Key': apiKey,
        'Accept': 'application/json'
      },
      timeout: API_TIMEOUT
    }
  );

  const report = data?.data || {};
  const abuseScore = report.abuseConfidenceScore || 0;
  const totalReports = report.totalReports || 0;

  const threats = [];
  if (abuseScore >= 50 || totalReports >= 20) {
    threats.push({
      source: 'AbuseIPDB',
      type: abuseScore >= 75 ? 'HIGH_ABUSE' : 'MODERATE_ABUSE',
      abuseScore,
      totalReports,
      ip,
      isp: report.isp || '',
      country: report.countryCode || ''
    });
  }

  return {
    source: 'AbuseIPDB',
    safe: abuseScore < 50 && totalReports < 20,
    abuseScore,
    totalReports,
    ip,
    threats,
    raw: report
  };
}

// ─────────────────────────────────────────────
// 5. SHODAN InternetDB — Free, no key required
//    Uses internetdb.shodan.io (free weekly-updated host data)
//    instead of api.shodan.io (requires paid plan)
// ─────────────────────────────────────────────
async function checkShodan(hostname) {
  // NOTE: No trusted-domain fast-path — all URLs evaluated.
  // Trusted-domain risk reduction is applied at the scoring layer.

  // Resolve hostname to IP
  let ip;
  try {
    const ips = await dnsResolve(hostname);
    ip = ips[0];
  } catch (e) {
    return { source: 'Shodan', safe: true, threats: [], note: 'DNS resolution failed' };
  }

  // InternetDB is free — no API key needed
  // Returns 404 when it has no data for the IP (common for cloud/CDN IPs)
  let data;
  try {
    const resp = await axios.get(
      `https://internetdb.shodan.io/${ip}`,
      { timeout: API_TIMEOUT }
    );
    data = resp.data;
  } catch (e) {
    if (e.response && e.response.status === 404) {
      // No data for this IP — treat as clean
      return { source: 'Shodan', safe: true, openPorts: 0, vulns: 0, tags: [], threats: [], note: 'No data available for this IP' };
    }
    throw e; // Re-throw other errors
  }

  const threats = [];
  const vulns = data?.vulns || [];
  const ports = data?.ports || [];
  const tags = data?.tags || [];

  // Flag if host has known vulnerabilities
  if (vulns.length > 0) {
    threats.push({
      source: 'Shodan',
      type: 'KNOWN_VULNERABILITIES',
      count: vulns.length,
      cves: vulns.slice(0, 5),
      ip
    });
  }

  // Flag suspicious open ports (common for malicious infrastructure)
  const suspiciousPorts = ports.filter(p => [4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337].includes(p));
  if (suspiciousPorts.length > 0) {
    threats.push({
      source: 'Shodan',
      type: 'SUSPICIOUS_PORTS',
      ports: suspiciousPorts,
      ip
    });
  }

  // Flag known-bad tags from Shodan
  const badTags = tags.filter(t => ['malware', 'phishing', 'c2', 'botnet', 'compromised'].includes(t.toLowerCase()));
  if (badTags.length > 0) {
    threats.push({
      source: 'Shodan',
      type: 'MALICIOUS_TAGS',
      tags: badTags,
      ip
    });
  }

  return {
    source: 'Shodan',
    safe: threats.length === 0,
    openPorts: ports.length,
    vulns: vulns.length,
    tags,
    threats,
    raw: { ip, ports, vulns: vulns.slice(0, 10), hostnames: data?.hostnames, tags }
  };
}


// ─────────────────────────────────────────────
// 6. HUGGINGFACE ML MODEL — BERT-based phishing URL classifier
//    Model: ealvaradob/bert-finetuned-phishing (97.17% accuracy)
//    Detects zero-day phishing URLs by learned textual patterns
//    Free HF Inference API: ~30k requests/month
// ─────────────────────────────────────────────
async function checkHuggingFace(url, apiToken) {
  if (!apiToken) return { source: 'ML Model (BERT)', safe: true, threats: [], note: 'No HuggingFace token configured', skipped: true };

  // NOTE: No trusted-domain fast-path — ML evaluates ALL URLs.
  // The BERT model's false-positive tendency on bare-domain URLs is handled
  // by the de-escalation multiplier and trusted-domain risk reduction at scoring.

  // New HF Inference Providers endpoint (old api-inference.huggingface.co is deprecated)
  const endpoint = 'https://router.huggingface.co/hf-inference/models/ealvaradob/bert-finetuned-phishing';
  const headers = {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${apiToken}`
  };

  const { data } = await axios.post(endpoint, { inputs: url }, { headers, timeout: HF_TIMEOUT });

  // Handle "model is loading" response
  if (data?.error && typeof data.error === 'string' && data.error.includes('loading')) {
    // Retry once after estimated wait
    const wait = Math.min((data.estimated_time || 10) * 1000, 20000);
    await new Promise(r => setTimeout(r, wait));
    const retry = await axios.post(endpoint, { inputs: url }, { headers, timeout: HF_TIMEOUT });
    return parseHFResponse(retry.data, url);
  }

  return parseHFResponse(data, url);
}

function parseHFResponse(data, url) {
  // Response: [[{label: "phishing", score: 0.97}, {label: "legitimate", score: 0.03}]]
  // or [[{label: "LABEL_1", score: 0.97}, {label: "LABEL_0", score: 0.03}]]
  const predictions = Array.isArray(data) ? (Array.isArray(data[0]) ? data[0] : data) : [];
  const phishingPred = predictions.find(p =>
    p.label && (p.label.toLowerCase() === 'phishing' || p.label === 'LABEL_1')
  );

  const phishingScore = phishingPred?.score || 0;
  const isPhishing = phishingScore > 0.75; // 75% threshold

  const threats = [];
  if (isPhishing) {
    threats.push({
      source: 'ML Model (BERT)',
      type: 'PHISHING_URL_PATTERN',
      confidence: `${(phishingScore * 100).toFixed(1)}%`,
      detail: `BERT model classified URL as phishing with ${(phishingScore * 100).toFixed(1)}% confidence`
    });
  }

  return {
    source: 'ML Model (BERT)',
    safe: !isPhishing,
    phishingScore,
    threats,
    raw: { predictions, phishingScore }
  };
}


// ─────────────────────────────────────────────
// 8. RDAP DOMAIN AGE CHECK — Free, no key required
//    Uses RDAP (Registration Data Access Protocol) to check domain registration date.
//    Phishing domains are almost always < 30 days old.
//    This is one of the strongest individual signals for phishing.
//    RDAP is the replacement for WHOIS — structured JSON, no API key needed.
// ─────────────────────────────────────────────
async function checkDomainAge(hostname) {
  let domain;
  try {
    const parts = hostname.split('.');
    // Get registrable domain (last 2 parts, or last 3 for co.uk etc.)
    const knownSecondLevel = ['co', 'com', 'org', 'net', 'gov', 'edu', 'ac', 'or', 'ne'];
    if (parts.length >= 3 && knownSecondLevel.includes(parts[parts.length - 2])) {
      domain = parts.slice(-3).join('.');
    } else {
      domain = parts.slice(-2).join('.');
    }
  } catch (e) {
    return { source: 'Domain Age (RDAP)', safe: true, threats: [], note: 'Could not extract domain', domainAgeDays: null };
  }

  try {
    // Use RDAP bootstrap to find the right RDAP server for this TLD
    const bootstrapResp = await axios.get(`https://rdap.org/domain/${domain}`, {
      timeout: RDAP_TIMEOUT,
      maxRedirects: 3,
      headers: { 'Accept': 'application/rdap+json, application/json' },
      validateStatus: (status) => status < 500
    });

    if (bootstrapResp.status === 404 || !bootstrapResp.data) {
      return { source: 'Domain Age (RDAP)', safe: true, threats: [], note: 'Domain not found in RDAP', domainAgeDays: null };
    }

    const rdapData = bootstrapResp.data;

    // Extract registration date from RDAP events
    const events = rdapData.events || [];
    let registrationDate = null;
    let lastChanged = null;

    for (const event of events) {
      if (event.eventAction === 'registration') {
        registrationDate = new Date(event.eventDate);
      }
      if (event.eventAction === 'last changed') {
        lastChanged = new Date(event.eventDate);
      }
    }

    if (!registrationDate) {
      return {
        source: 'Domain Age (RDAP)',
        safe: true,
        threats: [],
        note: 'No registration date found in RDAP response',
        domainAgeDays: null
      };
    }

    const now = new Date();
    const ageDays = Math.floor((now - registrationDate) / 86400000);

    const threats = [];
    let safe = true;

    // Very new domain (< 7 days) — extremely suspicious
    if (ageDays >= 0 && ageDays < 7) {
      safe = false;
      threats.push({
        source: 'Domain Age (RDAP)',
        type: 'DOMAIN_VERY_NEW',
        detail: `Domain registered only ${ageDays} day(s) ago — extremely new, very common for phishing`,
        ageDays
      });
    }
    // New domain (< 30 days) — suspicious
    else if (ageDays < 30) {
      safe = false;
      threats.push({
        source: 'Domain Age (RDAP)',
        type: 'DOMAIN_NEW',
        detail: `Domain registered ${ageDays} days ago (< 30 days) — new domains are frequently used for phishing`,
        ageDays
      });
    }
    // Recently registered (< 90 days) — mildly suspicious
    else if (ageDays < 90) {
      safe = false;
      threats.push({
        source: 'Domain Age (RDAP)',
        type: 'DOMAIN_RECENT',
        detail: `Domain registered ${ageDays} days ago (< 90 days) — relatively new domain`,
        ageDays
      });
    }

    return {
      source: 'Domain Age (RDAP)',
      safe,
      threats,
      domainAgeDays: ageDays,
      registrationDate: registrationDate.toISOString(),
      lastChanged: lastChanged ? lastChanged.toISOString() : null,
      raw: { domain, ageDays, registrationDate: registrationDate.toISOString() }
    };
  } catch (e) {
    const isTimeout = e.code === 'ECONNABORTED' || e.message?.includes('timeout');
    return {
      source: 'Domain Age (RDAP)',
      safe: true,
      threats: [],
      note: isTimeout ? 'RDAP lookup timed out' : `RDAP lookup failed: ${e.message}`,
      domainAgeDays: null
    };
  }
}


// ─────────────────────────────────────────────
// 9. REDIRECT CHAIN FOLLOWER
//    Follows HTTP redirects (301, 302, 303, 307, 308) up to 10 hops.
//    Phishing URLs often redirect through multiple intermediaries.
//    Returns the final destination URL and all intermediate hops.
//    Detects: cross-domain redirects, protocol downgrades, redirect loops.
// ─────────────────────────────────────────────
async function followRedirectChain(urlString) {
  const maxRedirects = 10;
  const chain = [urlString];
  let currentUrl = urlString;
  const threats = [];
  let crossDomainHops = 0;
  let protocolDowngrade = false;

  // NOTE: No trusted-domain fast-path — redirect chains are always analyzed.
  // Legitimate multi-hop redirects won't trigger phishing flags; only
  // suspicious cross-domain/protocol-downgrade patterns will.

  for (let hop = 0; hop < maxRedirects; hop++) {
    let parsed;
    try { parsed = new URL(currentUrl); } catch { break; }

    const isHttps = parsed.protocol === 'https:';
    const transport = isHttps ? https : http;

    const location = await new Promise((resolve) => {
      const req = transport.request(currentUrl, {
        method: 'HEAD',
        timeout: REDIRECT_TIMEOUT,
        rejectUnauthorized: false,
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) PhishNet/1.0',
          'Accept': 'text/html'
        }
      }, (res) => {
        if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location) {
          let loc = res.headers.location;
          // Handle relative redirects
          if (loc.startsWith('/')) {
            loc = `${parsed.protocol}//${parsed.host}${loc}`;
          } else if (!loc.startsWith('http')) {
            loc = `${parsed.protocol}//${parsed.host}/${loc}`;
          }
          resolve(loc);
        } else {
          resolve(null); // Not a redirect
        }
      });
      req.on('error', () => resolve(null));
      req.on('timeout', () => { req.destroy(); resolve(null); });
      req.end();
    });

    if (!location) break;

    // Check for redirect loop
    if (chain.includes(location)) {
      threats.push({
        source: 'Redirect Analysis',
        type: 'REDIRECT_LOOP',
        detail: `Redirect loop detected: ${location} already visited in chain`
      });
      break;
    }

    chain.push(location);

    // Check for cross-domain redirect
    try {
      const prevHost = new URL(currentUrl).hostname;
      const nextHost = new URL(location).hostname;
      if (prevHost !== nextHost) crossDomainHops++;
    } catch {}

    // Check for protocol downgrade (HTTPS → HTTP)
    try {
      const prevProto = new URL(currentUrl).protocol;
      const nextProto = new URL(location).protocol;
      if (prevProto === 'https:' && nextProto === 'http:') protocolDowngrade = true;
    } catch {}

    currentUrl = location;
  }

  // Analyze the chain
  const finalUrl = chain[chain.length - 1];
  const totalHops = chain.length - 1;

  if (totalHops >= 4) {
    threats.push({
      source: 'Redirect Analysis',
      type: 'EXCESSIVE_REDIRECTS',
      detail: `URL redirects ${totalHops} times before reaching destination — common obfuscation`,
      hops: totalHops
    });
  }

  if (crossDomainHops >= 2) {
    threats.push({
      source: 'Redirect Analysis',
      type: 'CROSS_DOMAIN_REDIRECTS',
      detail: `URL bounces across ${crossDomainHops} different domains — redirect chain obfuscation`,
      crossDomainHops
    });
  }

  if (protocolDowngrade) {
    threats.push({
      source: 'Redirect Analysis',
      type: 'PROTOCOL_DOWNGRADE',
      detail: 'Redirect chain downgrades from HTTPS to HTTP — possible SSL stripping attack'
    });
  }

  // Check if final destination differs from original
  let finalDomainDiffers = false;
  if (totalHops > 0) {
    try {
      const origHost = new URL(chain[0]).hostname;
      const finalHost = new URL(finalUrl).hostname;
      if (origHost !== finalHost) finalDomainDiffers = true;
    } catch {}
  }

  return {
    source: 'Redirect Analysis',
    safe: threats.length === 0,
    threats,
    chain,
    finalUrl,
    totalHops,
    crossDomainHops,
    protocolDowngrade,
    finalDomainDiffers,
    raw: { chain, totalHops, crossDomainHops, protocolDowngrade }
  };
}


// ─────────────────────────────────────────────
// 10. LOCAL URL HEURISTICS
//    Zero-latency URL structure analysis + typosquatting/homograph detection
//    + SSL certificate validation — all performed locally
// ─────────────────────────────────────────────

// Brand domains for typosquatting detection (60+ high-value targets)
const BRAND_DOMAINS = {
  // Tech giants
  'google': 'google.com', 'facebook': 'facebook.com', 'amazon': 'amazon.com',
  'apple': 'apple.com', 'microsoft': 'microsoft.com', 'netflix': 'netflix.com',
  'instagram': 'instagram.com', 'twitter': 'twitter.com', 'linkedin': 'linkedin.com',
  'github': 'github.com', 'dropbox': 'dropbox.com', 'yahoo': 'yahoo.com',
  'outlook': 'outlook.com', 'icloud': 'icloud.com', 'youtube': 'youtube.com',
  'tiktok': 'tiktok.com', 'snapchat': 'snapchat.com', 'pinterest': 'pinterest.com',
  'reddit': 'reddit.com', 'spotify': 'spotify.com', 'twitch': 'twitch.tv',
  'zoom': 'zoom.us', 'slack': 'slack.com', 'notion': 'notion.so',
  'adobe': 'adobe.com', 'docusign': 'docusign.com', 'salesforce': 'salesforce.com',
  // E-commerce & retail
  'walmart': 'walmart.com', 'ebay': 'ebay.com', 'etsy': 'etsy.com',
  'shopify': 'shopify.com', 'target': 'target.com', 'bestbuy': 'bestbuy.com',
  'costco': 'costco.com', 'aliexpress': 'aliexpress.com',
  // Financial & payment
  'paypal': 'paypal.com', 'chase': 'chase.com', 'bankofamerica': 'bankofamerica.com',
  'wellsfargo': 'wellsfargo.com', 'citibank': 'citibank.com', 'capitalone': 'capitalone.com',
  'amex': 'americanexpress.com', 'stripe': 'stripe.com', 'venmo': 'venmo.com',
  'zelle': 'zellepay.com', 'cashapp': 'cash.app', 'wise': 'wise.com',
  'robinhood': 'robinhood.com', 'fidelity': 'fidelity.com', 'schwab': 'schwab.com',
  // Crypto
  'coinbase': 'coinbase.com', 'binance': 'binance.com', 'kraken': 'kraken.com',
  'metamask': 'metamask.io', 'opensea': 'opensea.io', 'phantom': 'phantom.app',
  // Shipping & logistics
  'usps': 'usps.com', 'fedex': 'fedex.com', 'ups': 'ups.com', 'dhl': 'dhl.com',
  // Gaming
  'steam': 'steampowered.com', 'discord': 'discord.com', 'epicgames': 'epicgames.com',
  'roblox': 'roblox.com', 'playstation': 'playstation.com', 'xbox': 'xbox.com',
  // Communication
  'whatsapp': 'whatsapp.com', 'telegram': 'telegram.org', 'signal': 'signal.org',
  // Cloud & IT
  'aws': 'aws.amazon.com', 'cloudflare': 'cloudflare.com', 'digitalocean': 'digitalocean.com',
  // Government (common phishing targets)
  'irs': 'irs.gov', 'dmv': 'dmv.org', 'usaa': 'usaa.com',
};

// Suspicious keywords attackers combine with brand names (combo-squatting)
const COMBO_SQUAT_KEYWORDS = [
  'login', 'signin', 'sign-in', 'log-in', 'secure', 'security', 'verify',
  'verification', 'confirm', 'update', 'account', 'support', 'help', 'service',
  'billing', 'payment', 'wallet', 'recovery', 'alert', 'notification',
  'unlock', 'suspended', 'locked', 'verify2', 'auth', 'authentication',
  'portal', 'web', 'online', 'access', 'official', 'real', 'my', 'the',
  'new', 'free', 'promo', 'gift', 'reward', 'claim', 'prize', 'winner',
  'refund', 'invoice', 'receipt', 'delivery', 'shipping', 'track', 'package'
];

// Common keyboard-adjacent typo substitutions (QWERTY layout)
const KEYBOARD_ADJACENT = {
  'a': ['s','q','z','w'],   'b': ['v','n','g','h'],   'c': ['x','v','d','f'],
  'd': ['s','f','e','r','c','x'],  'e': ['w','r','d','s'],   'f': ['d','g','r','t','v','c'],
  'g': ['f','h','t','y','b','v'],  'h': ['g','j','y','u','n','b'],  'i': ['u','o','k','j'],
  'j': ['h','k','u','i','n','m'],  'k': ['j','l','i','o','m'],  'l': ['k','o','p'],
  'm': ['n','j','k'],   'n': ['b','m','h','j'],   'o': ['i','p','l','k'],
  'p': ['o','l'],       'q': ['w','a'],           'r': ['e','t','f','d'],
  's': ['a','d','w','e','x','z'],  't': ['r','y','g','f'],   'u': ['y','i','j','h'],
  'v': ['c','b','f','g'],   'w': ['q','e','s','a'],   'x': ['z','c','s','d'],
  'y': ['t','u','h','g'],   'z': ['x','a','s']
};

const HOMOGRAPHS = {
  // Latin ↔ Cyrillic (most common IDN attack vector)
  'a': ['\u0430', '\u0105', '\u03b1', '\u00e0', '\u00e1', '\u00e2', '\u00e3', '\u00e4', '@'],
  'b': ['\u0062', '\u0432', '\u0184', '\u13cf'],   // Cyrillic в, Cherokee
  'c': ['\u0441', '\u00e7', '\u0188', '\u03f2'],   // Cyrillic с, Latin ç, Greek ϲ
  'd': ['\u0501', '\u13e7', '\u0256'],             // Cyrillic ԁ, Cherokee
  'e': ['\u0435', '\u0119', '\u03b5', '\u00e8', '\u00e9', '\u00ea', '\u0117', '3'],
  'f': ['\u017f'],                                    // Latin long s ſ
  'g': ['\u0261', '9', 'q'],                          // Latin script g variant
  'h': ['\u04bb', '\u0570'],                         // Cyrillic һ, Armenian հ
  'i': ['\u0456', '\u0131', '\u00ec', '\u00ed', '1', 'l', '|', '!'],
  'j': ['\u0458', '\u029d'],                         // Cyrillic ј
  'k': ['\u043a', '\u0138'],                         // Cyrillic к
  'l': ['\u04cf', '\u0196', '1', 'I', '|', '!'],    // Cyrillic ӏ
  'm': ['\u043c', '\u217f', 'rn'],                   // Cyrillic м, Roman numeral, rn combo
  'n': ['\u043f', '\u00f1', '\u0578'],              // Cyrillic п, Armenian ո
  'o': ['\u043e', '\u00f8', '\u03bf', '\u00f2', '\u00f3', '\u00f4', '\u00f6', '0'],
  'p': ['\u0440', '\u03c1', '\u0420'],              // Cyrillic р, Greek ρ, Cyrillic Р
  'q': ['\u051b', '\u0566'],                         // Cyrillic ԛ, Armenian զ
  'r': ['\u0433', '\u027e'],                         // Cyrillic г, Latin r with fishhook
  's': ['\u0455', '\u015f', '$', '5'],               // Cyrillic ѕ, Turkish ş
  't': ['\u0442', '\u03c4', '+'],                    // Cyrillic т, Greek τ
  'u': ['\u03bc', '\u00f9', '\u00fa', '\u00fb', '\u00fc', 'v'],
  'v': ['\u0475', '\u03bd', 'u'],                    // Cyrillic ѵ, Greek ν
  'w': ['\u0461', 'vv', 'vu'],                        // Cyrillic ѡ, double-v trick
  'x': ['\u0445', '\u00d7', '\u04b3'],              // Cyrillic х, multiplication sign
  'y': ['\u0443', '\u00fd', '\u0263'],              // Cyrillic у
  'z': ['\u0437', '\u01b6'],                         // Cyrillic з
};

const SUSPICIOUS_TLDS = [
  // Free / abused registration TLDs
  '.xyz','.top','.click','.link','.work','.gq','.ml','.cf','.tk','.ga',
  '.buzz','.live','.online','.site','.club','.icu','.vip','.win','.loan','.racing',
  '.stream','.download','.review','.cricket','.science','.date','.faith','.party',
  '.trade','.bid','.webcam','.gdn','.kim','.men','.rocks','.pw','.ws','.cc',
  // New gTLDs heavily abused for phishing
  '.support','.help','.services','.solutions','.tech','.space','.website',
  '.fun','.monster','.rest','.surf','.bar','.cyou','.cfd','.sbs','.lol',
  '.quest','.boutique','.fit','.bond','.icu','.hair','.beauty','.makeup',
  '.skin','.boats','.homes','.autos','.yachts'
];

const URL_SHORTENERS = [
  'bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','is.gd','buff.ly',
  'adf.ly','shorte.st','bc.vc','j.mp','v.gd','cutt.ly','rb.gy','shorturl.at','tiny.cc',
  // Additional popular & abused shorteners
  'rebrand.ly','bl.ink','short.io','tny.im','clck.ru','qps.ru','u.to',
  'surl.li','dub.sh','t.ly','lnkd.in','amzn.to','youtu.be','s.id',
  'shorten.asia','rotf.lol','shorturl.asia','1url.cz','hyperurl.co',
  'urlzs.com','zzb.bz','linktr.ee','solo.to','hec.su','linklyhq.com'
];

const SUSPICIOUS_PATH_PATTERNS = [
  // Authentication / credential harvesting
  /login.*verify/i, /secure.*update/i, /account.*confirm/i, /verify.*identity/i,
  /password.*reset/i, /billing.*update/i, /suspended.*account/i, /unlock.*account/i,
  /verify.*email/i, /confirm.*payment/i, /signin.*update/i, /webscr.*cmd/i,
  // Financial bait
  /invoice.*download/i, /payment.*pending/i, /refund.*claim/i, /tax.*return/i,
  /wire.*transfer/i, /bank.*statement/i, /credit.*card.*update/i,
  // Urgency / social engineering keywords in path
  /urgent.*action/i, /immediate.*required/i, /final.*warning/i, /last.*chance/i,
  /expire.*soon/i, /limited.*time/i, /act.*now/i, /48.*hours/i,
  // Credential reset scare
  /unusual.*activity/i, /security.*alert/i, /unauthorized.*access/i,
  /compromised.*account/i, /breach.*notification/i,
  // Common phishing kit paths
  /\.php\?.*(?:redirect|token|ref|session|auth)/i,
  /wp-(?:admin|includes|content).*(?:login|verify)/i,
];

// File extensions commonly used in phishing lures
const SUSPICIOUS_EXTENSIONS = [
  '.exe','.scr','.bat','.cmd','.com','.vbs','.vbe','.js','.jse','.wsf',
  '.wsh','.ps1','.psc1','.msi','.msp','.hta','.cpl','.inf','.reg',
  '.rgs','.pif','.application','.gadget','.jar','.docm','.xlsm','.pptm',
  '.dotm','.xltm','.potm','.sldm','.iso','.img','.vhd'
];

// Data URI schemes used for evasion
const EVASION_SCHEMES = ['data:', 'javascript:', 'vbscript:', 'blob:'];

const TRUSTED_DOMAINS = [
  'google.com','facebook.com','amazon.com','apple.com','microsoft.com','paypal.com',
  'netflix.com','twitter.com','x.com','instagram.com','linkedin.com','github.com',
  'stackoverflow.com','youtube.com','wikipedia.org','reddit.com','yahoo.com','bing.com',
  'dropbox.com','icloud.com','outlook.com','office.com','live.com','replit.com',
  'npmjs.com','golang.org','python.org','mozilla.org','w3.org','cloudflare.com',
  'amazonaws.com','azure.com','heroku.com','vercel.app','netlify.app',
  'whatsapp.com','telegram.org','discord.com','steampowered.com','spotify.com',
  'twitch.tv','zoom.us','slack.com','notion.so','figma.com','canva.com',
  'appspot.com','googleapis.com','gstatic.com','cdn.jsdelivr.net',
  // Local / development — never flag
  'localhost', '127.0.0.1', '[::1]', '0.0.0.0'
];

function levenshtein(a, b) {
  const m = [];
  for (let i = 0; i <= b.length; i++) m[i] = [i];
  for (let j = 0; j <= a.length; j++) m[0][j] = j;
  for (let i = 1; i <= b.length; i++)
    for (let j = 1; j <= a.length; j++)
      m[i][j] = b[i-1] === a[j-1] ? m[i-1][j-1] : Math.min(m[i-1][j-1]+1, m[i][j-1]+1, m[i-1][j]+1);
  return m[b.length][a.length];
}

function detectHomograph(hostname, brand) {
  for (const [ch, lookalikes] of Object.entries(HOMOGRAPHS)) {
    for (const la of lookalikes) {
      if (hostname.includes(la) && brand.includes(ch)) {
        const escaped = la.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        const normalized = hostname.replace(new RegExp(escaped, 'g'), ch);
        if (normalized.includes(brand)) return true;
      }
    }
  }
  return false;
}

/**
 * Normalize a hostname by stripping hyphens, dots (except TLD separator),
 * and common char substitutions to detect deliberate obfuscation.
 */
/**
 * Shannon entropy — measures mathematical randomness of a string.
 * High entropy (>3.5) indicates random/generated domain names.
 * Legitimate domains (google, facebook) have lower entropy (~2.5-3.2).
 * DGA (domain generation algorithm) domains have entropy >3.8.
 */
function shannonEntropy(str) {
  if (!str || str.length === 0) return 0;
  const freq = {};
  for (const ch of str.toLowerCase()) {
    freq[ch] = (freq[ch] || 0) + 1;
  }
  const len = str.length;
  let entropy = 0;
  for (const ch in freq) {
    const p = freq[ch] / len;
    if (p > 0) entropy -= p * Math.log2(p);
  }
  return entropy;
}

/**
 * Consonant-to-total ratio — another randomness indicator.
 * Most natural language words have 40-60% consonants.
 * Random strings tend to have >70% consonants.
 */
function consonantRatio(str) {
  if (!str) return 0;
  const lower = str.toLowerCase().replace(/[^a-z]/g, '');
  if (lower.length === 0) return 0;
  const consonants = (lower.match(/[bcdfghjklmnpqrstvwxyz]/g) || []).length;
  return consonants / lower.length;
}

function normalizeForTypo(str) {
  return str
    .replace(/[-_.]/g, '')          // Remove separators: pay-pal → paypal
    .replace(/ph/g, 'f')            // phishing → fishing
    .replace(/0/g, 'o')             // g00gle → google
    .replace(/1/g, 'l')             // app1e → apple
    .replace(/3/g, 'e')             // fac3book → facebook
    .replace(/4/g, 'a')             // 4mazon → amazon
    .replace(/5/g, 's')             // micro5oft → microsoft
    .replace(/\$/g, 's')            // pay$al → paysal
    .replace(/@/g, 'a')             // @mazon → amazon
    .replace(/!/g, 'i')             // appl! → appli
    .toLowerCase();
}

/**
 * Check if a domain looks like a keyboard-adjacent typo of a brand.
 * E.g., "googlr" → 'r' is adjacent to 'e' on QWERTY → typo of "google"
 */
function isKeyboardTypo(input, brand) {
  if (input.length !== brand.length) return false;
  let diffs = 0;
  for (let i = 0; i < input.length; i++) {
    if (input[i] !== brand[i]) {
      diffs++;
      if (diffs > 1) return false;  // More than 1 diff = not a simple typo
      const adj = KEYBOARD_ADJACENT[brand[i]];
      if (!adj || !adj.includes(input[i])) return false;
    }
  }
  return diffs === 1;
}

/**
 * Detect IDN/Punycode domains — domains starting with xn-- are
 * internationalized domain names that may visually mimic Latin domains.
 */
function isPunycode(hostname) {
  return hostname.split('.').some(label => label.startsWith('xn--'));
}

/**
 * Check if a hostname contains a brand split by hyphens or dots.
 * E.g., "pay-pal.com", "face-book.net", "app.le-id.com"
 */
function hasHyphenSquat(hostname, brand) {
  // Remove TLD, then join all parts and remove hyphens
  const withoutTLD = hostname.split('.').slice(0, -1).join('');
  const collapsed = withoutTLD.replace(/-/g, '');
  return collapsed.includes(brand) && hostname.includes('-');
}

function checkSSLCertSingle(hostname, method = 'HEAD') {
  return new Promise((resolve) => {
    const req = https.request(
      { hostname, port: 443, method, rejectUnauthorized: false, timeout: 6000,
        // Ensure TLS socket is fully established before reading cert
        agent: false },
      (res) => {
        // Consume the response to prevent socket hang
        res.resume();
        const socket = res.socket;

        // Try with full chain first, fall back to leaf cert
        let cert = socket.getPeerCertificate?.(true);
        if (!cert || Object.keys(cert).length === 0) {
          cert = socket.getPeerCertificate?.(false);
        }

        if (!cert || Object.keys(cert).length === 0) {
          return resolve({ valid: false, issue: 'No certificate' });
        }

        const now = new Date();
        const validFrom = new Date(cert.valid_from);
        const validTo = new Date(cert.valid_to);
        const daysLeft = Math.ceil((validTo - now) / 86400000);
        const certAgeDays = Math.ceil((now - validFrom) / 86400000);
        const validityDays = Math.ceil((validTo - validFrom) / 86400000);
        const selfSigned = cert.issuer?.CN === cert.subject?.CN;
        const issuerOrg = cert.issuer?.O || 'Unknown';
        const subjectCN = cert.subject?.CN || '';
        const authorized = socket.authorized || false;

        // ── TLS version ──
        const tlsVersion = socket.getProtocol ? socket.getProtocol() : null;
        const weakTLS = tlsVersion && (tlsVersion === 'TLSv1' || tlsVersion === 'TLSv1.1');

        // ── Subject Alternative Names ──
        const sanRaw = cert.subjectaltname || '';
        const sanList = sanRaw.split(',').map(s => s.trim().replace('DNS:', ''));

        // ── Hostname match check ──
        // The cert should cover the hostname via CN or SAN
        let hostnameMatch = false;
        const allNames = [subjectCN, ...sanList].filter(Boolean);
        for (const name of allNames) {
          if (name === hostname) { hostnameMatch = true; break; }
          // Wildcard: *.example.com matches sub.example.com
          if (name.startsWith('*.')) {
            const wildcard = name.slice(2);
            if (hostname.endsWith(wildcard) && hostname.split('.').length === wildcard.split('.').length + 1) {
              hostnameMatch = true; break;
            }
          }
        }

        // ── Free/DV CA detection ──
        const freeCAs = ["let's encrypt", 'letsencrypt', 'zerossl', 'buypass', 'ssl.com free'];
        const issuerLower = (issuerOrg + ' ' + (cert.issuer?.CN || '')).toLowerCase();
        const isFreeCert = freeCAs.some(ca => issuerLower.includes(ca));

        // ── Wildcard abuse check ──
        const hasWildcard = allNames.some(n => n.startsWith('*.'));

        // ── Build anomalies list ──
        const anomalies = [];

        if (selfSigned) anomalies.push('Self-signed certificate');
        if (!authorized && !selfSigned) anomalies.push('Certificate not trusted by system CA store');
        if (!hostnameMatch) anomalies.push(`Certificate CN/SAN does not match hostname "${hostname}"`);
        if (daysLeft < 0) anomalies.push(`Certificate expired ${Math.abs(daysLeft)} days ago`);
        else if (daysLeft < 7) anomalies.push(`Certificate expires in ${daysLeft} days`);
        if (certAgeDays < 7) anomalies.push(`Certificate issued only ${certAgeDays} day(s) ago — very new`);
        if (validityDays < 30 && validityDays > 0) anomalies.push(`Very short validity period: ${validityDays} days`);
        if (weakTLS) anomalies.push(`Weak TLS version: ${tlsVersion}`);
        if (isFreeCert && certAgeDays < 14) anomalies.push(`Free CA (${issuerOrg}) + newly issued — common phishing pattern`);
        if (hasWildcard && isFreeCert) anomalies.push('Wildcard cert from free CA');

        resolve({
          valid: daysLeft > 0,
          authorized,
          selfSigned,
          hostnameMatch,
          daysUntilExpiry: daysLeft,
          certAgeDays,
          validityDays,
          issuer: issuerOrg,
          subject: subjectCN,
          isFreeCert,
          tlsVersion: tlsVersion || 'Unknown',
          weakTLS,
          hasWildcard,
          sanCount: sanList.filter(Boolean).length,
          anomalies
        });
      }
    );
    req.on('error', (e) => resolve({
      valid: false,
      issue: e.message.includes('certificate') ? 'Invalid SSL certificate' : 'Connection failed',
      anomalies: [e.message.includes('certificate') ? 'SSL certificate validation failed' : 'Could not connect']
    }));
    req.on('timeout', () => { req.destroy(); resolve({ valid: false, issue: 'Timeout', anomalies: ['SSL connection timed out'] }); });
    req.end();
  });
}

// Retry wrapper: if HEAD returns "No certificate", retry with GET
// Some servers/CDNs handle HEAD differently or close the socket early
async function checkSSLCert(hostname) {
  const result = await checkSSLCertSingle(hostname, 'HEAD');
  if (result.issue === 'No certificate') {
    // Retry with GET — more reliable for certificate extraction
    const retry = await checkSSLCertSingle(hostname, 'GET');
    if (!retry.issue || retry.issue === 'Connection failed' || retry.issue === 'Timeout') {
      return retry; // retry succeeded or at least not "No certificate"
    }
  }
  return result;
}

// ─────────────────────────────────────────────
// CERTIFICATE TRANSPARENCY (crt.sh — free, no key)
// ─────────────────────────────────────────────
async function checkCertTransparency(hostname) {
  try {
    const resp = await axios.get(`https://crt.sh/?q=${encodeURIComponent(hostname)}&output=json`, {
      timeout: 6000,
      headers: { 'User-Agent': 'PhishNet/1.0' }
    });
    if (!resp.data || !Array.isArray(resp.data)) return null;

    const certs = resp.data;
    const totalCerts = certs.length;

    // Find how recently the first cert was issued
    const now = new Date();
    let newestCertDays = Infinity;
    let oldestCertDays = 0;
    for (const c of certs) {
      const entryDate = new Date(c.entry_timestamp || c.not_before);
      const daysSinceIssue = Math.ceil((now - entryDate) / 86400000);
      if (daysSinceIssue < newestCertDays) newestCertDays = daysSinceIssue;
      if (daysSinceIssue > oldestCertDays) oldestCertDays = daysSinceIssue;
    }

    return {
      totalCerts,
      newestCertDays: newestCertDays === Infinity ? null : newestCertDays,
      oldestCertDays,
      domainFirstSeen: oldestCertDays, // days since first ever cert was logged
    };
  } catch (e) {
    return null; // CT check is best-effort
  }
}

async function checkURLHeuristics(urlString) {
  const threats = [];
  const structureIssues = [];
  const typoIssues = [];
  let sslInfo = null;

  // Parse URL
  let parsed;
  try {
    if (!urlString.startsWith('http://') && !urlString.startsWith('https://')) urlString = 'https://' + urlString;
    parsed = new URL(urlString);
  } catch (e) {
    return { source: 'URL Heuristics', safe: false, threats: [{ source: 'URL Heuristics', type: 'INVALID_URL', detail: 'Could not parse URL' }], raw: {} };
  }

  const hostname = parsed.hostname;
  const parts = hostname.split('.');
  const domain = parts.length >= 2 ? parts.slice(-2).join('.') : hostname;
  const baseName = parts.length >= 2 ? parts[parts.length - 2] : parts[0];
  const tld = '.' + parts[parts.length - 1];

  // NOTE: No trusted-domain fast-path — heuristics evaluate ALL URLs.
  // Trusted-domain risk reduction is applied at the scoring layer.
  const isTrusted = TRUSTED_DOMAINS.some(td => hostname === td || hostname.endsWith('.' + td) || domain === td);

  // ── URL Structure Analysis (instant — pure string ops) ──
  const fullURL = urlString;
  const pathLower = (parsed.pathname + parsed.search + parsed.hash).toLowerCase();

  // --- Basic protocol & host checks ---
  if (parsed.protocol === 'http:') structureIssues.push('Uses insecure HTTP');
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) structureIssues.push('IP address as hostname');
  if (SUSPICIOUS_TLDS.includes(tld)) structureIssues.push(`Suspicious TLD: ${tld}`);
  if (URL_SHORTENERS.includes(hostname)) structureIssues.push('URL shortener — destination hidden');
  if (parsed.port && !['80', '443', ''].includes(parsed.port)) structureIssues.push(`Non-standard port: ${parsed.port}`);

  // --- Subdomain analysis ---
  const subdomainCount = parts.length - 2;
  if (subdomainCount > 3) structureIssues.push(`Excessive subdomains (${subdomainCount})`);
  // Subdomain that looks like an IP to confuse users
  if (subdomainCount > 0 && /^\d{1,3}[-.]\d{1,3}[-.]\d{1,3}[-.]\d{1,3}/.test(parts[0])) {
    structureIssues.push('IP-like subdomain — visual obfuscation');
  }

  // --- Path / query suspicious patterns ---
  let suspiciousPathCount = 0;
  for (const p of SUSPICIOUS_PATH_PATTERNS) {
    if (p.test(parsed.pathname) || p.test(parsed.search)) { suspiciousPathCount++; }
  }
  if (suspiciousPathCount >= 2) structureIssues.push(`Multiple phishing keywords in URL (${suspiciousPathCount} patterns matched)`);
  else if (suspiciousPathCount === 1) structureIssues.push('Suspicious keywords in URL path');

  // --- Encoding / obfuscation ---
  if (/%[0-9a-f]{2}.*%[0-9a-f]{2}/i.test(parsed.search)) structureIssues.push('Encoded characters in query');
  if (fullURL.includes('@')) structureIssues.push('@ symbol — possible URL obfuscation');
  // Double URL encoding (%%25XX or %25XX) — evasion technique
  if (/%25[0-9a-f]{2}/i.test(fullURL)) structureIssues.push('Double URL encoding detected — evasion technique');
  // Hex/octal IP obfuscation (0x7f.0x0.0x0.0x1 or 0177.0.0.01)
  if (/0x[0-9a-f]+\./i.test(hostname) || /^0\d+\./.test(hostname)) {
    structureIssues.push('Hex/octal IP encoding — obfuscation technique');
  }

  // --- URL length anomalies ---
  if (fullURL.length > 500) structureIssues.push(`Extremely long URL (${fullURL.length} chars)`);
  else if (fullURL.length > 200) structureIssues.push('Unusually long URL');

  // --- Path depth ---
  const pathSegments = parsed.pathname.split('/').filter(Boolean);
  if (pathSegments.length > 7) structureIssues.push(`Deep path nesting (${pathSegments.length} levels)`);

  // --- Domain entropy (randomness) — phishing domains are often random strings ---
  // Uses Shannon entropy (mathematical) + consonant ratio for robust randomness detection
  const domainEntropy = shannonEntropy(baseName);
  const domainConsonantRatio = consonantRatio(baseName);
  if (baseName.length >= 6) {
    // Shannon entropy > 3.8 on a 6+ char domain is very likely DGA/random
    if (domainEntropy > 3.8 && baseName.length >= 8) {
      structureIssues.push(`High entropy domain: "${baseName}" (Shannon entropy: ${domainEntropy.toFixed(2)} — likely algorithmically generated)`);
    }
    // Lower threshold but combined with consonant ratio — catches more subtle randomness
    else if (domainEntropy > 3.3 && domainConsonantRatio > 0.75 && baseName.length >= 10) {
      structureIssues.push(`Random-looking domain: "${baseName}" (entropy: ${domainEntropy.toFixed(2)}, consonant ratio: ${(domainConsonantRatio*100).toFixed(0)}%)`);
    }
    // Mix of many digits + letters = generated domain
    const digits = (baseName.match(/[0-9]/g) || []).length;
    if (digits >= 3 && baseName.length >= 8 && digits / baseName.length > 0.3) {
      structureIssues.push(`Domain contains many digits mixed with letters: "${baseName}" (${digits} digits in ${baseName.length} chars)`);
    }
    // Consecutive consonants cluster — natural words rarely have 5+ consonants in a row
    if (/[bcdfghjklmnpqrstvwxyz]{5,}/i.test(baseName)) {
      structureIssues.push(`Unpronounceable consonant cluster in domain: "${baseName}"`);
    }
  }

  // --- Suspicious file extensions in path (executable lures) ---
  // Only check the actual path, not query params (to avoid matching .com in embedded URLs)
  const pathOnly = parsed.pathname.toLowerCase();
  for (const ext of SUSPICIOUS_EXTENSIONS) {
    if (pathOnly.endsWith(ext) || pathOnly.includes(ext + '/')) {
      structureIssues.push(`Suspicious file extension in URL: ${ext}`);
      break;
    }
  }

  // --- Double extensions (document.pdf.exe) ---
  const lastSegment = pathSegments[pathSegments.length - 1] || '';
  const extMatches = lastSegment.match(/\.[a-z0-9]{2,5}/gi) || [];
  if (extMatches.length >= 2) {
    structureIssues.push(`Double file extension: "${lastSegment}" — common malware trick`);
  }

  // --- Data URI / javascript: / blob: in URL (XSS/redirect evasion) ---
  for (const scheme of EVASION_SCHEMES) {
    if (fullURL.toLowerCase().includes(scheme)) {
      structureIssues.push(`Evasion scheme detected: ${scheme}`);
      break;
    }
  }

  // --- Open redirect patterns ---
  if (/[?&](redirect|url|next|return|goto|dest|destination|continue|rurl|target|link)=/i.test(parsed.search)) {
    structureIssues.push('Open redirect parameter detected — may bounce to malicious page');
  }

  // --- Base64 in URL (used to hide payloads) ---
  if (/[?&#\/=]([A-Za-z0-9+\/]{40,}={0,2})/.test(fullURL)) {
    structureIssues.push('Long Base64-like string in URL — possible encoded payload');
  }

  // --- Homograph dot abuse (using unusual Unicode dots) ---
  if (/[\u2024\u2025\u2026\uFE52\uFF0E]/.test(fullURL)) {
    structureIssues.push('Unicode dot characters — visual domain obfuscation');
  }

  // --- Multiple redirect hops embedded in URL ---
  const redirectCount = (fullURL.match(/https?:\/\//gi) || []).length;
  if (redirectCount >= 3) {
    structureIssues.push(`Multiple URLs embedded (${redirectCount} http(s):// found) — redirect chain`);
  } else if (redirectCount === 2) {
    structureIssues.push('URL contains another URL — possible redirect');
  }

  // --- Hyphen count in domain (needed by keyword check below) ---
  const hyphenCount = (baseName.match(/-/g) || []).length;

  // --- Suspicious keywords in domain name (credential / urgency bait) ---
  const DOMAIN_KEYWORDS = [
    'login', 'signin', 'signup', 'verify', 'secure', 'account', 'update',
    'confirm', 'billing', 'password', 'suspend', 'unlock', 'alert', 'banking',
    'wallet', 'recover', 'authenticate', 'validation', 'authorize'
  ];
  // Split baseName on hyphens for EXACT word matching (avoids "accountant" matching "account")
  const domainWords = baseName.toLowerCase().split(/-/).filter(Boolean);
  const matchedDomainKeywords = DOMAIN_KEYWORDS.filter(kw => domainWords.includes(kw));
  if (matchedDomainKeywords.length >= 2) {
    structureIssues.push(`Multiple suspicious keywords in domain: ${matchedDomainKeywords.join(', ')}`);
  } else if (matchedDomainKeywords.length === 1 && hyphenCount >= 2) {
    // Single keyword + multi-word domain (2+ hyphens) = suspicious combo
    structureIssues.push(`Suspicious keyword "${matchedDomainKeywords[0]}" in multi-word domain`);
  }

  // --- Excessive hyphens in domain (phishing domains often chain words with hyphens) ---
  if (hyphenCount >= 3) {
    structureIssues.push(`Excessive hyphens in domain (${hyphenCount}) — uncommon for legitimate sites`);
  }

  // --- Brand name in URL path (lure using well-known brand as path segment) ---
  const BRAND_NAMES_FOR_PATH = [
    'paypal', 'chase', 'wellsfargo', 'bankofamerica', 'citibank', 'hsbc',
    'amazon', 'apple', 'microsoft', 'google', 'facebook', 'netflix',
    'instagram', 'linkedin', 'twitter', 'dropbox', 'icloud', 'outlook',
    'yahoo', 'ebay', 'usps', 'fedex', 'dhl', 'irs', 'coinbase', 'binance'
  ];
  const pathWords = parsed.pathname.toLowerCase().split(/[/.\-_]+/).filter(w => w.length >= 3);
  const brandInPath = BRAND_NAMES_FOR_PATH.filter(b => pathWords.includes(b));
  if (brandInPath.length > 0) {
    structureIssues.push(`Brand name "${brandInPath[0]}" in URL path — possible impersonation lure`);
  }

  // --- Trigger threat at 1+ issues now (was 2+), with severity tiers ---
  if (structureIssues.length > 0) {
    threats.push({
      source: 'URL Heuristics',
      type: 'SUSPICIOUS_STRUCTURE',
      count: structureIssues.length,
      details: structureIssues.join('; ')
    });
  }

  // ── Typosquatting / Homograph Detection (instant — string ops) ──
  const normalizedBase = normalizeForTypo(baseName);
  const fullHostNoTLD = parts.slice(0, -1).join('.');  // everything except TLD

  for (const [brand, official] of Object.entries(BRAND_DOMAINS)) {
    if (domain === official || hostname.endsWith('.' + official)) continue;
    const officialDomain = official.split('.')[0]; // e.g. 'google' from 'google.com'

    // 1. Brand name present in base domain but not the official domain
    if (baseName.includes(brand)) {
      typoIssues.push(`Contains "${brand}" but is not ${official}`);
    }

    // 2. Levenshtein near-match on base domain name
    //    Uses edit-distance ratio normalization: distance_ratio = edit_distance / max(domain_length, brand_length)
    //    Flag if ratio ≤ 0.25 AND brand substring is present (or very close match).
    //    This scales better across short vs long domains compared to fixed thresholds.
    const dist = levenshtein(baseName, brand);
    const maxLen = Math.max(baseName.length, brand.length);
    const distRatio = maxLen > 0 ? dist / maxLen : 1;
    const brandSubstringPresent = baseName.includes(brand) || normalizedBase.includes(brand);
    // Primary: ratio-based detection (scales across all domain lengths)
    if (dist > 0 && distRatio <= 0.25 && baseName.length >= 4 && (brandSubstringPresent || distRatio <= 0.15)) {
      typoIssues.push(`Similar to "${brand}" (edit distance: ${dist}, ratio: ${distRatio.toFixed(2)} — within 25% threshold)`);
    }
    // Fallback: fixed thresholds for backward compatibility (catches edge cases ratio might miss)
    else if (dist > 0 && dist <= (brand.length <= 3 ? 0 : brand.length <= 5 ? 1 : 2)
             && baseName.length >= 4 && Math.abs(baseName.length - brand.length) <= 2) {
      typoIssues.push(`Similar to "${brand}" (edit distance: ${dist})`);
    }

    // 3. Homograph/IDN visual spoofing
    if (detectHomograph(hostname, brand)) {
      typoIssues.push(`Homograph attack mimicking "${brand}"`);
    }

    // 4. Normalized match (char substitution: g00gle, app1e, amaz0n)
    if (normalizedBase !== baseName && normalizedBase.includes(brand) && !baseName.includes(brand)) {
      typoIssues.push(`Character substitution detected: "${baseName}" normalizes to contain "${brand}"`);
    }

    // 5. Keyboard-adjacent typo (googlr, facebok, amazom)
    if (isKeyboardTypo(baseName, brand)) {
      typoIssues.push(`Keyboard typo of "${brand}" — "${baseName}"`);
    }

    // 6. Hyphen/separator squatting (pay-pal.com, face-book.net)
    if (hasHyphenSquat(hostname, brand)) {
      typoIssues.push(`Hyphen-squatting: "${hostname}" splits brand "${brand}" with separators`);
    }

    // 7. Combo-squatting (paypal-login.com, google-verify.net)
    if (!baseName.includes(brand)) {
      for (const kw of COMBO_SQUAT_KEYWORDS) {
        const combos = [
          `${brand}${kw}`, `${brand}-${kw}`, `${kw}${brand}`, `${kw}-${brand}`,
          `${brand}${kw}s`, `${kw}s${brand}`
        ];
        const hostLower = hostname.toLowerCase();
        if (combos.some(c => hostLower.includes(c))) {
          typoIssues.push(`Combo-squatting: hostname contains "${brand}" + suspicious keyword "${kw}"`);
          break; // One keyword match per brand is enough
        }
      }
    }

    // 8. Subdomain brand abuse (paypal.evil-login.com — brand in subdomain but not main domain)
    if (subdomainCount > 0) {
      const subdomains = parts.slice(0, -2).join('.');
      if (subdomains.includes(brand) && !baseName.includes(brand)) {
        typoIssues.push(`Brand "${brand}" in subdomain but main domain is "${domain}" — subdomain abuse`);
      }
    }

    // 9. TLD-swap (google.net, paypal.xyz, amazon.org when official is .com)
    const officialTLD = '.' + official.split('.').pop();
    if (baseName === brand && tld !== officialTLD) {
      typoIssues.push(`TLD swap: "${hostname}" uses ${tld} instead of official ${officialTLD}`);
    }
  }

  // 10. Punycode/IDN domain (xn--) — even without matching a specific brand, these are suspicious
  if (isPunycode(hostname)) {
    typoIssues.push(`Internationalized Domain Name (IDN/Punycode) detected: "${hostname}" — may visually mimic a Latin domain`);
  }

  // 11. Brand name embedded with extra chars (e.g., "googlle", "paypall", "faceboook")
  for (const [brand] of Object.entries(BRAND_DOMAINS)) {
    if (baseName.includes(brand)) continue; // Already caught above
    // Check for character doubling: "googlle" vs "google"
    const deduplicated = baseName.replace(/(.)\1+/g, '$1'); // collapse repeated chars
    if (deduplicated === brand && baseName !== brand && baseName.length <= brand.length + 2) {
      typoIssues.push(`Character repetition: "${baseName}" looks like "${brand}" with doubled letters`);
    }
  }

  // Deduplicate typo issues (multiple checks may flag same thing)
  const uniqueTypoIssues = [...new Set(typoIssues)];

  if (uniqueTypoIssues.length > 0) {
    threats.push({
      source: 'URL Heuristics',
      type: 'TYPOSQUATTING',
      count: uniqueTypoIssues.length,
      details: uniqueTypoIssues.join('; ')
    });
  }

  // ── Enhanced SSL Certificate Check (light network call) ──
  if (parsed.protocol === 'https:') {
    try {
      // Run SSL check and Certificate Transparency lookup in parallel
      const [sslResult, ctResult] = await Promise.all([
        checkSSLCert(hostname),
        checkCertTransparency(hostname)
      ]);
      sslInfo = sslResult;
      if (ctResult) sslInfo.ct = ctResult;

      if (!sslInfo.valid && sslInfo.issue !== 'Connection failed' && sslInfo.issue !== 'Timeout') {
        // ─ Certificate invalid / expired / missing ─
        // Note: "Connection failed" and "Timeout" are NOT certificate issues — they just
        // mean we couldn't reach the server (firewalled, slow, etc.). Don't penalize.
        threats.push({ source: 'URL Heuristics', type: 'SSL_ANOMALY', detail: sslInfo.issue || 'Invalid SSL certificate' });
      } else {
        // Certificate exists and hasn't expired — run detailed checks against anomalies

        // Self-signed
        if (sslInfo.selfSigned) {
          threats.push({ source: 'URL Heuristics', type: 'SELF_SIGNED_CERT', detail: 'Self-signed SSL certificate — not issued by a trusted CA' });
        }

        // Not trusted by system CA store (but not self-signed — means broken chain)
        if (!sslInfo.authorized && !sslInfo.selfSigned) {
          threats.push({ source: 'URL Heuristics', type: 'UNTRUSTED_CERT', detail: 'Certificate not trusted by system CA store — possible chain issue' });
        }

        // Hostname mismatch
        if (sslInfo.hostnameMatch === false) {
          threats.push({ source: 'URL Heuristics', type: 'CERT_MISMATCH', detail: `Certificate CN/SAN does not match hostname "${hostname}"` });
        }

        // Expiring soon (< 7 days)
        if (sslInfo.daysUntilExpiry < 7) {
          threats.push({ source: 'URL Heuristics', type: 'SSL_EXPIRING', detail: `Certificate expires in ${sslInfo.daysUntilExpiry} day(s)` });
        }

        // Newly issued certificate (< 7 days old) — strong phishing indicator
        if (sslInfo.certAgeDays !== undefined && sslInfo.certAgeDays < 7) {
          threats.push({ source: 'URL Heuristics', type: 'CERT_NEWLY_ISSUED', detail: `Certificate issued only ${sslInfo.certAgeDays} day(s) ago — common for phishing campaigns` });
        }

        // Very short validity period (< 30 days) — phishing certs are short-lived
        if (sslInfo.validityDays !== undefined && sslInfo.validityDays < 30) {
          threats.push({ source: 'URL Heuristics', type: 'CERT_SHORT_VALIDITY', detail: `Certificate validity only ${sslInfo.validityDays} days — unusually short` });
        }

        // Weak TLS version (1.0 or 1.1 — deprecated and insecure)
        if (sslInfo.weakTLS) {
          threats.push({ source: 'URL Heuristics', type: 'WEAK_TLS', detail: `Using deprecated ${sslInfo.tlsVersion} — vulnerable to known attacks` });
        }

        // Free CA + newly issued — classic phishing combo
        if (sslInfo.isFreeCert && sslInfo.certAgeDays !== undefined && sslInfo.certAgeDays < 14) {
          threats.push({ source: 'URL Heuristics', type: 'FREE_CA_NEW_CERT', detail: `Free CA (${sslInfo.issuer}) cert issued ${sslInfo.certAgeDays} day(s) ago — common phishing pattern` });
        }

        // Wildcard from free CA — low-trust wildcard
        if (sslInfo.hasWildcard && sslInfo.isFreeCert) {
          threats.push({ source: 'URL Heuristics', type: 'WILDCARD_FREE_CA', detail: 'Wildcard certificate from free CA — unusual for legitimate services' });
        }

        // ── Certificate Transparency Log Analysis ──
        if (ctResult) {
          // Domain first seen very recently in CT logs — phishing domains are brand new
          if (ctResult.domainFirstSeen !== undefined && ctResult.domainFirstSeen < 30) {
            threats.push({
              source: 'URL Heuristics',
              type: 'CT_NEW_DOMAIN',
              detail: `Domain first appeared in Certificate Transparency logs ${ctResult.domainFirstSeen} day(s) ago — very new domain`
            });
          }
          // Only 1-2 certs ever issued for this domain — thin history
          if (ctResult.totalCerts <= 2 && ctResult.domainFirstSeen < 60) {
            threats.push({
              source: 'URL Heuristics',
              type: 'CT_THIN_HISTORY',
              detail: `Only ${ctResult.totalCerts} certificate(s) ever logged for this domain — minimal history`
            });
          }
        }
      }
    } catch (e) { /* SSL check failure is non-critical */ }
  } else {
    sslInfo = { valid: false, issue: 'Not HTTPS', anomalies: ['Site uses insecure HTTP'] };
    threats.push({ source: 'URL Heuristics', type: 'NO_HTTPS', detail: 'Site does not use HTTPS — all traffic is unencrypted' });
  }

  return {
    source: 'URL Heuristics',
    safe: threats.length === 0,
    threats,
    structureIssues: structureIssues.length,
    typosquattingDetected: uniqueTypoIssues.length > 0,
    typosquattingCount: uniqueTypoIssues.length,
    raw: { structureIssues, typoIssues: uniqueTypoIssues, ssl: sslInfo }
  };
}


// ─────────────────────────────────────────────
// COMBINED MULTI-SOURCE SCAN
// ─────────────────────────────────────────────

/**
 * Scan a URL against all available threat intelligence APIs in parallel.
 * Returns a combined verdict with per-source results.
 * 
 * @param {string} url - The URL to scan
 * @param {object} keys - API keys: { googleSafeBrowsing, virusTotal, abuseIPDB, shodan, huggingFace }
 * @returns {{ status: string, threats: object[], sources: object[], sourcesChecked: string[] }}
 */
async function scanUrlMultiSource(url, keys = {}) {
  let hostname = '';
  try {
    hostname = new URL(url).hostname;
  } catch (e) {
    hostname = url;
  }

  // Skip scanning for localhost / private IPs — always safe
  const isLocal = hostname === 'localhost' || hostname === '[::1]' || hostname === '0.0.0.0'
    || /^127\./.test(hostname)
    || /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)/.test(hostname);
  if (isLocal) {
    console.log(`[ThreatIntel] Skipping local/dev URL: ${url}`);
    return {
      status: 'SAFE',
      threats: [],
      sources: [{ source: 'PhishNet', safe: true, details: { note: 'Local/development address — not scanned' } }],
      sourcesChecked: ['PhishNet (local)'],
      errors: [],
      score: 0
    };
  }

  // ── Early-exit blocking: if a high-confidence authoritative source (GSB, VT, URLhaus)
  //    fires, we don't need to wait for all 10 sources. We abort remaining slow checks
  //    and proceed to scoring immediately, reducing attack dwell time. ──

  const sourceNames = [
    'Google Safe Browsing', 'VirusTotal', 'URLhaus', 'AbuseIPDB', 'Shodan',
    'ML Model (BERT)', 'URL Heuristics', 'Domain Age (RDAP)', 'Redirect Analysis',
    ...(headlessBrowser ? ['Headless Browser Analysis'] : [])
  ];

  // High-confidence authoritative sources — a hit on ANY of these triggers early exit
  const EARLY_EXIT_SOURCES = new Set([0, 1, 2]); // indices: GSB, VT, URLhaus

  // Launch ALL checks in parallel — each wrapped in try/catch so one failure doesn't kill others
  // Sources 1-9 are the original checks, source 10 is headless browser (optional)
  const baseChecks = [
    checkGoogleSafeBrowsing(url, keys.googleSafeBrowsing),
    checkVirusTotal(url, keys.virusTotal),
    checkURLhaus(url, keys.urlhaus),
    checkAbuseIPDB(hostname, keys.abuseIPDB),
    checkShodan(hostname),              // InternetDB is free, no key needed
    checkHuggingFace(url, keys.huggingFace),  // ML model — zero-day phishing detection
    checkURLHeuristics(url),            // Local heuristics — typosquatting, SSL, structure
    checkDomainAge(hostname),           // RDAP domain registration age — free, no key
    followRedirectChain(url),           // Redirect chain analysis — follow all hops
  ];

  // 10. Headless Browser Analysis (optional — requires Chrome)
  if (headlessBrowser) {
    baseChecks.push(
      headlessBrowser.analyzeWithHeadlessBrowser(url).catch(err => ({
        source: 'Headless Browser Analysis',
        safe: true,
        threats: [],
        available: false,
        raw: { error: err.message }
      }))
    );
  }

  // Collect results as they arrive — early-exit if authoritative source flags the URL
  const settledResults = new Array(baseChecks.length).fill(null);
  let earlyExitTriggered = false;
  let earlyExitReason = '';

  const racePromise = new Promise((resolveRace) => {
    let settledCount = 0;
    const totalChecks = baseChecks.length;

    baseChecks.forEach((check, idx) => {
      Promise.resolve(check)
        .then(value => { settledResults[idx] = { status: 'fulfilled', value }; })
        .catch(reason => { settledResults[idx] = { status: 'rejected', reason }; })
        .finally(() => {
          settledCount++;

          // Check if this result triggers early exit
          if (!earlyExitTriggered && EARLY_EXIT_SOURCES.has(idx)) {
            const r = settledResults[idx];
            if (r.status === 'fulfilled' && r.value && !r.value.safe) {
              const val = r.value;
              const name = sourceNames[idx];

              // GSB hit → immediate exit (authoritative blacklist)
              if (idx === 0 && val.threats?.length > 0) {
                earlyExitTriggered = true;
                earlyExitReason = `Google Safe Browsing flagged: ${val.threats.map(t => t.type).join(', ')}`;
              }
              // VT ≥ 3 malicious engines → immediate exit
              else if (idx === 1 && (val.malicious || 0) >= 3) {
                earlyExitTriggered = true;
                earlyExitReason = `VirusTotal: ${val.malicious}/${val.total} engines flagged malicious`;
              }
              // URLhaus hit → immediate exit (known malware distribution)
              else if (idx === 2 && val.threats?.length > 0) {
                earlyExitTriggered = true;
                earlyExitReason = `URLhaus: known malware distribution URL`;
              }

              if (earlyExitTriggered) {
                console.log(`[ThreatIntel] ⚡ EARLY EXIT for ${url} — ${earlyExitReason} (after ${settledCount}/${totalChecks} sources)`);
                // Give a 500ms grace period for other fast sources that may have already returned
                setTimeout(() => resolveRace(), 500);
                return;
              }
            }
          }

          // All checks done — resolve normally
          if (settledCount === totalChecks) {
            resolveRace();
          }
        });
    });
  });

  await racePromise;

  // Use whatever results have settled by now
  const checks = settledResults;

  const sources = [];
  const allThreats = [];
  const sourcesChecked = [];
  const errors = [];

  checks.forEach((result, idx) => {
    const name = sourceNames[idx];
    // null = source hadn't settled when early-exit fired (or API key not configured)
    if (!result) {
      if (earlyExitTriggered) {
        sourcesChecked.push(`${name} (aborted — early exit)`);
      }
      return;
    }
    if (result.status === 'fulfilled' && result.value) {
      const val = result.value;
      sourcesChecked.push(name);
      sources.push({
        source: name,
        safe: val.safe,
        details: (() => {
          const { raw, ...rest } = val;
          // Include compact SSL summary for URL Heuristics
          if (raw?.ssl) {
            const s = raw.ssl;
            rest.ssl = {
              valid: s.valid,
              authorized: s.authorized,
              selfSigned: s.selfSigned,
              hostnameMatch: s.hostnameMatch,
              daysUntilExpiry: s.daysUntilExpiry,
              certAgeDays: s.certAgeDays,
              validityDays: s.validityDays,
              issuer: s.issuer,
              subject: s.subject,
              isFreeCert: s.isFreeCert,
              tlsVersion: s.tlsVersion,
              weakTLS: s.weakTLS,
              hasWildcard: s.hasWildcard,
              sanCount: s.sanCount,
              anomalies: s.anomalies || [],
              ct: s.ct || null
            };
          }
          return rest;
        })()
      });
      if (val.threats && val.threats.length > 0) {
        allThreats.push(...val.threats);
      }
    } else if (result.status === 'rejected') {
      errors.push({ source: name, error: result.reason?.message || 'Unknown error' });
      sourcesChecked.push(`${name} (error)`);
    }
    // null means API key not configured — skip silently
  });

  // ─── Calibrated Probabilistic Risk Engine ───
  // Each source contributes a normalized risk in [0, 1].
  // Final risk_score = min(1.0, sum(all contributions)).
  // Verdict:  >= 0.80 → MALICIOUS,  >= 0.40 → SUSPICIOUS,  else SAFE

  const contributions = {
    gsb: 0,
    virustotal: 0,
    urlhaus: 0,
    abuseipdb: 0,
    shodan: 0,
    ml_model: 0,
    domain_age: 0,
    redirect: 0,
    headless_browser: 0,
    heuristics: { typosquat: 0, structure: 0, ssl: 0, entropy: 0 }
  };
  const explanationParts = [];

  // ── First pass: compute external-only risk to decide de-escalation ──
  // Must use the SAME thresholds as actual contribution logic — VT 1-2/94 is noise
  let externalRisk = 0;
  for (const src of sources) {
    if (src.safe) continue;
    if (src.source.includes('ML Model') || src.source.includes('Heuristics')) continue;
    switch (src.source) {
      case 'Google Safe Browsing': externalRisk += 0.95; break;
      case 'VirusTotal': {
        const vtM = src.details?.malicious || 0;
        const vtT = src.details?.total || 94;
        const vtS = src.details?.suspicious || 0;
        // Only count VT if it would actually contribute (3+ malicious, or 1+ mal with 2+ sus)
        if (vtM >= 3 || (vtM >= 1 && vtS >= 2)) {
          externalRisk += 0.85 * (vtM / Math.max(vtT, 1));
        }
        break;
      }
      case 'URLhaus': externalRisk += 0.80; break;
      case 'AbuseIPDB': {
        const as = src.details?.abuseScore || 0;
        if (as >= 50) externalRisk += 0.20 * (as / 100);
        break;
      }
      case 'Shodan': externalRisk += 0.05; break;
      case 'Domain Age (RDAP)': {
        const ageDays = src.details?.domainAgeDays;
        if (ageDays !== null && ageDays !== undefined) {
          if (ageDays < 7) externalRisk += 0.30;
          else if (ageDays < 30) externalRisk += 0.20;
          else if (ageDays < 90) externalRisk += 0.08;
        }
        break;
      }
    }
  }
  const allExternalClean = externalRisk === 0;
  const deescalationMultiplier = allExternalClean ? 0.3 : 1.0;

  // ── Second pass: compute per-source contributions ──
  for (const src of sources) {
    if (src.safe) continue;
    switch (src.source) {

      case 'Google Safe Browsing':
        contributions.gsb = 0.95;
        explanationParts.push('Google Safe Browsing blacklisted this URL (risk +0.95)');
        break;

      case 'VirusTotal': {
        const vtMalicious = src.details?.malicious || 0;
        const vtTotal = src.details?.total || 94;
        // Ignore 1-2 engine detections with no suspicious — noise from obscure AV vendors
        const vtSuspicious = src.details?.suspicious || 0;
        if (vtMalicious >= 3 || (vtMalicious >= 1 && vtSuspicious >= 2)) {
          contributions.virustotal = 0.85 * (vtMalicious / Math.max(vtTotal, 1));
          explanationParts.push(`VirusTotal: ${vtMalicious}/${vtTotal} engines flagged (risk +${contributions.virustotal.toFixed(3)})`);
        }
        break;
      }

      case 'URLhaus':
        contributions.urlhaus = 0.80;
        explanationParts.push('URLhaus: known malware distribution URL (risk +0.80)');
        break;

      case 'AbuseIPDB': {
        const abuseScore = src.details?.abuseScore || 0;
        if (abuseScore >= 50) {
          contributions.abuseipdb = 0.20 * (abuseScore / 100);
          explanationParts.push(`AbuseIPDB: abuse score ${abuseScore}% (risk +${contributions.abuseipdb.toFixed(3)})`);
        }
        break;
      }

      case 'Shodan':
        contributions.shodan = 0.05;
        explanationParts.push('Shodan: suspicious infrastructure indicators (risk +0.05)');
        break;

      case 'Domain Age (RDAP)': {
        const ageDays = src.details?.domainAgeDays;
        if (ageDays !== null && ageDays !== undefined) {
          // Domain age is an external factual check — NOT de-escalated
          // Very new domains are the strongest phishing indicator
          if (ageDays < 7) {
            contributions.domain_age = 0.30;
            explanationParts.push(`Domain Age: registered only ${ageDays} day(s) ago — extremely new (risk +0.300, not de-escalated)`);
          } else if (ageDays < 30) {
            contributions.domain_age = 0.20;
            explanationParts.push(`Domain Age: registered ${ageDays} days ago — new domain (risk +0.200, not de-escalated)`);
          } else if (ageDays < 90) {
            contributions.domain_age = 0.08;
            explanationParts.push(`Domain Age: registered ${ageDays} days ago — relatively new (risk +0.080, not de-escalated)`);
          }
        }
        break;
      }

      case 'Redirect Analysis': {
        const hops = src.details?.totalHops || 0;
        const crossDomain = src.details?.crossDomainHops || 0;
        const downgrade = src.details?.protocolDowngrade || false;
        // Redirect analysis is factual — NOT de-escalated
        let redirectContrib = 0;
        if (hops >= 4) redirectContrib += 0.10;
        if (crossDomain >= 2) redirectContrib += 0.10;
        if (downgrade) redirectContrib += 0.08;
        // Redirect loop is very suspicious
        const hasLoop = src.details?.threats?.some(t => t.type === 'REDIRECT_LOOP');
        if (hasLoop) redirectContrib += 0.15;
        contributions.redirect = Math.min(0.25, redirectContrib);
        if (contributions.redirect > 0) {
          const parts = [];
          if (hops >= 4) parts.push(`${hops} redirect hops`);
          if (crossDomain >= 2) parts.push(`${crossDomain} cross-domain bounces`);
          if (downgrade) parts.push('HTTPS→HTTP downgrade');
          if (hasLoop) parts.push('redirect loop');
          explanationParts.push(`Redirect chain: ${parts.join(', ')} (risk +${contributions.redirect.toFixed(3)}, not de-escalated)`);
        }
        break;
      }

      case 'ML Model (BERT)': {
        const phishProb = src.details?.phishingScore || 0;
        const rawContribution = 0.60 * phishProb;
        contributions.ml_model = rawContribution * deescalationMultiplier;
        if (contributions.ml_model > 0.001) {
          const deNote = allExternalClean ? ' (de-escalated ×0.3 — all external APIs clean)' : '';
          explanationParts.push(`ML BERT model: ${(phishProb * 100).toFixed(1)}% phishing probability (risk +${contributions.ml_model.toFixed(3)}${deNote})`);
        }
        if (allExternalClean && phishProb > 0.75) {
          console.log(`[ThreatIntel] ML de-escalation: all 6 external APIs clean, ML at ${(phishProb * 100).toFixed(1)}% — contribution reduced from ${rawContribution.toFixed(3)} to ${contributions.ml_model.toFixed(3)}`);
        }
        break;
      }

      case 'URL Heuristics': {
        const structCount = src.details?.structureIssues || 0;
        const hasTypo = src.details?.typosquattingDetected || false;
        const typoCount = src.details?.typosquattingCount || 0;
        const heuristicThreats = src.details?.threats || [];

        // ── Typosquatting contribution ──
        // Typosquatting is NOT de-escalated: it's a factual observation about the domain
        // name mimicking a known brand. External databases not having indexed a new phishing
        // domain doesn't make the impersonation less real (zero-day phishing).
        if (hasTypo) {
          contributions.heuristics.typosquat = 0.40;
          explanationParts.push(`Typosquatting: ${typoCount} signal(s) detected (risk +0.400 — not de-escalated, domain name impersonation is a structural fact)`);
        }

        // ── Structure contribution ──
        // Multiple structural red flags are converging evidence regardless of API coverage.
        // Graduate de-escalation: more issues = less damping.
        if (structCount > 0) {
          let rawStruct;
          if (structCount >= 5)      rawStruct = 0.25;
          else if (structCount >= 3) rawStruct = 0.15;
          else if (structCount >= 2) rawStruct = 0.10;
          else                       rawStruct = 0.05;

          // Graduated de-escalation by signal count:
          //   5+ issues → no de-escalation (×1.0) — too many converging signals to ignore
          //   3-4 issues → mild de-escalation (×0.7)
          //   1-2 issues → standard de-escalation (×0.3)
          let structMultiplier;
          if (!allExternalClean)            structMultiplier = 1.0;
          else if (structCount >= 5)        structMultiplier = 1.0;
          else if (structCount >= 3)        structMultiplier = 0.7;
          else                              structMultiplier = 0.3;

          contributions.heuristics.structure = rawStruct * structMultiplier;
          const deNote = allExternalClean && structMultiplier < 1.0 ? ` (de-escalated ×${structMultiplier})` : '';
          explanationParts.push(`Structure: ${structCount} anomaly/anomalies (risk +${contributions.heuristics.structure.toFixed(3)}${deNote})`);
        }

        // ── Entropy / obfuscation contribution ──
        // Encoding/obfuscation is a deliberate evasion technique — use mild de-escalation (×0.5)
        const entropyKeywords = ['random-looking', 'encoded', 'obfuscation', 'base64', 'double url encoding', 'hex/octal', 'entropy'];
        const structIssuesList = src.details?.raw?.structureIssues || [];
        const rawStructIssues = Array.isArray(structIssuesList) ? structIssuesList : [];
        const entropyIssues = rawStructIssues.filter(iss =>
          entropyKeywords.some(kw => (typeof iss === 'string' ? iss : '').toLowerCase().includes(kw))
        );
        if (entropyIssues.length > 0) {
          const rawEntropy = 0.20;
          const entropyMult = allExternalClean ? 0.5 : 1.0;
          contributions.heuristics.entropy = rawEntropy * entropyMult;
          const deNote = allExternalClean ? ' (de-escalated ×0.5)' : '';
          explanationParts.push(`Entropy/obfuscation: ${entropyIssues.length} indicator(s) (risk +${contributions.heuristics.entropy.toFixed(3)}${deNote})`);
        }

        // ── SSL contribution ──
        // Critical SSL issues (self-signed, mismatch, untrusted) use mild de-escalation (×0.5)
        // Informational SSL issues (no HTTPS, expiring) use standard (×0.3)
        const sslTypes = [
          'SSL_ANOMALY', 'SELF_SIGNED_CERT', 'CERT_MISMATCH', 'UNTRUSTED_CERT',
          'CERT_NEWLY_ISSUED', 'FREE_CA_NEW_CERT', 'CERT_SHORT_VALIDITY', 'WILDCARD_FREE_CA',
          'SSL_EXPIRING', 'WEAK_TLS', 'NO_HTTPS', 'CT_NEW_DOMAIN', 'CT_THIN_HISTORY'
        ];
        const criticalSSLTypes = ['SSL_ANOMALY', 'SELF_SIGNED_CERT', 'CERT_MISMATCH', 'UNTRUSTED_CERT', 'FREE_CA_NEW_CERT'];
        const sslThreats = heuristicThreats.filter(t => sslTypes.includes(t.type));
        if (sslThreats.length > 0) {
          const hasCriticalSSL = sslThreats.some(t => criticalSSLTypes.includes(t.type));
          const rawSSL = Math.min(0.20, 0.08 * sslThreats.length);
          const sslMult = allExternalClean ? (hasCriticalSSL ? 0.5 : 0.3) : 1.0;
          contributions.heuristics.ssl = rawSSL * sslMult;
          const deNote = allExternalClean ? ` (de-escalated ×${sslMult})` : '';
          const sslLabels = sslThreats.map(t => t.type).join(', ');
          explanationParts.push(`SSL: ${sslThreats.length} issue(s) [${sslLabels}] (risk +${contributions.heuristics.ssl.toFixed(3)}${deNote})`);
        }
        break;
      }

      // ── Headless Browser Analysis (source #10) ──
      case 'Headless Browser Analysis': {
        if (src.details?.available === false) break; // Chrome not installed
        const hbThreats = src.details?.threats || [];
        if (hbThreats.length > 0) {
          // Classify headless findings
          const hasHiddenForm = hbThreats.some(t => t.type === 'HIDDEN_LOGIN_FORM' || t.type === 'CROSS_ORIGIN_CREDENTIAL_FORM');
          const hasObfuscation = hbThreats.some(t => t.type === 'HEAVY_JS_OBFUSCATION' || t.type === 'JS_OBFUSCATION');
          const hasJsRedirect = hbThreats.some(t => t.type === 'JS_REDIRECT_CROSS_DOMAIN');
          const hasBrandImpersonation = hbThreats.some(t => t.type === 'BRAND_IMPERSONATION_TITLE');
          const hasSuspiciousBehavior = hbThreats.some(t => t.type === 'SUSPICIOUS_JS_BEHAVIOR');

          let hbContrib = 0;
          if (hasHiddenForm)          hbContrib += 0.30;
          if (hasObfuscation)         hbContrib += 0.15;
          if (hasJsRedirect)          hbContrib += 0.10;
          if (hasBrandImpersonation)  hbContrib += 0.20;
          if (hasSuspiciousBehavior)  hbContrib += 0.25;
          contributions.headless_browser = Math.min(0.50, hbContrib);

          if (contributions.headless_browser > 0) {
            const parts = [];
            if (hasHiddenForm)          parts.push('hidden login form');
            if (hasObfuscation)         parts.push('JS obfuscation');
            if (hasJsRedirect)          parts.push('JS cross-domain redirect');
            if (hasBrandImpersonation)  parts.push('brand impersonation in page');
            if (hasSuspiciousBehavior)  parts.push('suspicious JS behavior');
            explanationParts.push(`Headless Browser: ${parts.join(', ')} (risk +${contributions.headless_browser.toFixed(3)})`);
          }
        }
        break;
      }
    }
  }

  // ── Signal corroboration bonus ──
  // When the ML model AND heuristic structure analysis independently converge on phishing,
  // the combined evidence is much stronger than either alone. This bonus is NOT de-escalated
  // because it represents agreement between two independent detection methods.
  let corroborationBonus = 0;
  const mlPhishProb = (() => {
    const mlSrc = sources.find(s => s.source === 'ML Model (BERT)' && !s.safe);
    return mlSrc?.details?.phishingScore || 0;
  })();
  const totalHeuristicIssues = contributions.heuristics.structure > 0 || contributions.heuristics.entropy > 0 || contributions.heuristics.ssl > 0;
  const structIssueCount = (() => {
    const hSrc = sources.find(s => s.source === 'URL Heuristics');
    return hSrc?.details?.structureIssues || 0;
  })();

  if (allExternalClean && mlPhishProb > 0.6 && structIssueCount >= 1) {
    // Two independent local methods agree — strong corroboration
    if (mlPhishProb > 0.8 && structIssueCount >= 2) {
      corroborationBonus = 0.20;
    } else if (mlPhishProb > 0.6 && structIssueCount >= 3) {
      corroborationBonus = 0.20;
    } else {
      corroborationBonus = 0.12;
    }
    explanationParts.push(`Signal corroboration: ML model (${(mlPhishProb*100).toFixed(0)}%) and structural analysis (${structIssueCount} issues) independently converge (bonus +${corroborationBonus.toFixed(2)})`);
  }

  // ── ADAPTIVE TEMPORAL RISK (ATR) ──
  // Models real attacker economics:
  //  • Attackers register cheap throwaway domains for phishing campaigns (< 30 days old).
  //    When a fresh domain ALSO has suspicious URL structure/ML signals, the risk
  //    escalates exponentially — these two factors together are the #1 phishing fingerprint.
  //  • Legitimate businesses maintain domains for years. Long-lived domains with clean
  //    external reputation earn gradual trust that dampens local false positives.

  const heuristicTotal = contributions.heuristics.typosquat
    + contributions.heuristics.structure
    + contributions.heuristics.ssl
    + contributions.heuristics.entropy;

  // Extract domain age from source data
  const domainAgeSrc = sources.find(s => s.source === 'Domain Age (RDAP)');
  const domainAgeDays = domainAgeSrc?.details?.domainAgeDays ?? null;
  const preLexical = contributions.ml_model + heuristicTotal + (contributions.headless_browser || 0);

  let temporalPenalty = 0;
  let temporalTrust = 0;

  // 1. EXPONENTIAL PENALTY: New domain (< 30 days) + lexical risk signals
  //    Power-law amplification: penalty = base × ageFactor^1.2 × (lexical/threshold)^1.8
  //    This produces super-linear scaling: a 3-day-old domain with strong ML+heuristic
  //    signals gets a much larger penalty than either factor alone.
  //    Examples:
  //      Day 0, lexical 0.80 → 0.30 × 1.0  × 3.56 = 0.350 (capped)
  //      Day 5, lexical 0.50 → 0.30 × 0.78 × 1.63 = 0.281
  //      Day 15, lexical 0.40 → 0.30 × 0.43 × 1.15 = 0.149
  //      Day 25, lexical 0.20 → 0.30 × 0.13 × 0.53 = 0.021
  if (domainAgeDays !== null && domainAgeDays < 30 && preLexical > 0.1) {
    const ageFactor = (30 - domainAgeDays) / 30; // 1.0 at day 0, 0 at day 30
    temporalPenalty = 0.30 * Math.pow(ageFactor, 1.2) * Math.pow(preLexical / 0.3, 1.8);
    temporalPenalty = Math.min(0.35, Math.max(0, temporalPenalty)); // cap [0, 0.35]
    contributions.temporal_risk = temporalPenalty;
    explanationParts.push(
      `Adaptive Temporal Risk: new domain (${domainAgeDays}d) × lexical signals `
      + `(${preLexical.toFixed(2)}) → exponential penalty +${temporalPenalty.toFixed(3)}`
    );
  }

  // 2. GRADUAL TRUST: Long-lived domain (≥ 1 year) + clean external reputation
  //    Logarithmic scaling means trust accumulates slowly and can't be faked by squatting.
  //    Trust discount dampens lexical-only false positives for established domains.
  //    Examples:
  //      1 year  → 0.000 (baseline, no discount yet)
  //      2 years → 0.050
  //      5 years → 0.116
  //      10 years → 0.150 (capped)
  if (domainAgeDays !== null && domainAgeDays >= 365 && allExternalClean) {
    const yearsFactor = domainAgeDays / 365;
    temporalTrust = Math.min(0.15, 0.05 * Math.log2(yearsFactor));
    if (temporalTrust > 0.001) {
      contributions.temporal_trust = -temporalTrust;
      explanationParts.push(
        `Temporal Trust: established domain (~${Math.floor(domainAgeDays / 365)}yr) `
        + `with clean external history → lexical dampening -${temporalTrust.toFixed(3)}`
      );
    } else {
      temporalTrust = 0;
    }
  }

  // ── DUAL RISK ARCHITECTURE: Infrastructure vs Lexical ──
  // Separating these two fundamentally different risk types prevents lexical tricks
  // alone from overpowering strong clean reputation, while still detecting fresh
  // phishing domains that external databases haven't indexed yet.

  // Infrastructure risk: reputation-based signals from external databases + domain age
  // Now includes temporal penalty (new-domain × lexical synergy)
  const infraRisk = Math.min(1.0,
    contributions.gsb
    + contributions.virustotal
    + contributions.urlhaus
    + contributions.abuseipdb
    + contributions.shodan
    + contributions.domain_age
    + contributions.redirect
    + temporalPenalty
  );

  // Lexical risk: local analysis of URL structure, typosquatting, ML model, JS behavior
  // Now reduced by temporal trust for established domains
  const lexicalRisk = Math.max(0, Math.min(1.0,
    contributions.ml_model
    + heuristicTotal
    + (contributions.headless_browser || 0)
    + corroborationBonus
    - temporalTrust
  ));

  // Combined risk: 1 - (1 - infra_risk) * (1 - lexical_risk)
  // This produces a probabilistic union: both streams contribute independently.
  // If either is very high, the combined score is high.
  // If both are moderate, the combined score is higher than either alone.
  const combinedRisk = 1 - (1 - infraRisk) * (1 - lexicalRisk);

  // Legacy additive score for backward compatibility / validation
  // Also incorporates temporal adjustments
  const additiveRisk = Math.max(0, Math.min(1.0,
    contributions.gsb + contributions.virustotal + contributions.urlhaus
    + contributions.abuseipdb + contributions.shodan + contributions.domain_age
    + contributions.redirect + contributions.ml_model + heuristicTotal
    + (contributions.headless_browser || 0) + corroborationBonus
    + temporalPenalty - temporalTrust
  ));

  // Use the higher of combined and additive to ensure we never lose sensitivity
  let riskScore = Math.max(combinedRisk, additiveRisk);

  // ── Apply user feedback calibration weights (if available) ──
  let calibratedContributions = contributions;
  if (feedbackModule) {
    try {
      calibratedContributions = feedbackModule.applyCalibration(contributions);
    } catch (_) { /* calibration is optional */ }
  }

  // ── Trusted domain risk reduction (NOT absolute override) ──
  // Trusted domains get a risk REDUCTION, not a forced-safe override.
  // This prevents exploitation via compromised legitimate domains:
  //  - A legitimate domain that starts hosting phishing WILL still be flagged
  //    if GSB/VT/URLhaus flag it, or if DOM/redirect behavior is malicious.
  //  - When authoritative feeds are clean, the trusted status applies an 85%
  //    risk reduction — enough to suppress minor noise but NOT enough to hide
  //    genuine behavioral red flags (hidden forms, credential exfiltration, etc.)
  //
  // Risk reduction tiers:
  //   Trusted + all authoritative clean → multiply risk by 0.15 (85% reduction)
  //   Trusted + authoritative flagged   → NO reduction (domain may be compromised)
  const hostClean = hostname.replace(/^www\./, '');
  const isTrustedDomain = TRUSTED_DOMAINS.some(td => hostClean === td || hostClean.endsWith('.' + td));
  const authoritativeClean = sources.every(s => {
    const name = s.source || (s.details && s.details.source);
    if (['Google Safe Browsing', 'VirusTotal', 'URLhaus'].includes(name)) {
      return s.safe !== false; // true or undefined/null = clean
    }
    return true; // non-authoritative sources don't block the reduction
  });

  let trustedReduction = 0;
  if (isTrustedDomain && authoritativeClean) {
    const TRUST_MULTIPLIER = 0.15; // Keep 15% of computed risk
    const originalRisk = riskScore;
    riskScore = riskScore * TRUST_MULTIPLIER;
    trustedReduction = originalRisk - riskScore;
    // Scale contributions proportionally (for UI accuracy)
    for (const key of Object.keys(contributions)) {
      if (typeof contributions[key] === 'number') contributions[key] *= TRUST_MULTIPLIER;
      else if (typeof contributions[key] === 'object') {
        for (const sub of Object.keys(contributions[key])) contributions[key][sub] *= TRUST_MULTIPLIER;
      }
    }
    if (trustedReduction > 0.001) {
      console.log(`[ThreatIntel] Trusted domain risk reduction for ${hostname}: ${originalRisk.toFixed(4)} → ${riskScore.toFixed(4)} (×${TRUST_MULTIPLIER}, saved ${trustedReduction.toFixed(4)})`);
    }
  } else if (isTrustedDomain && !authoritativeClean) {
    console.log(`[ThreatIntel] ⚠️ Trusted domain ${hostname} has authoritative flags — NO risk reduction applied (possible compromise)`);
  }

  // ── Verdict ──
  let status;
  if (riskScore >= 0.80) {
    status = 'MALICIOUS';
  } else if (riskScore >= 0.40) {
    status = 'SUSPICIOUS';
  } else {
    status = 'SAFE';
  }

  // Build human-readable explanation
  let explanation;
  if (explanationParts.length === 0) {
    explanation = 'All threat intelligence sources report this URL as clean.';
  } else {
    const deNote = allExternalClean ? ' Note: all external threat intelligence databases returned clean — ML and heuristic signals were de-escalated (×0.3).' : '';
    explanation = explanationParts.join('. ') + '.' + deNote;
    // Add dual-risk architecture note
    explanation += ` [Dual-risk: infra=${infraRisk.toFixed(3)}, lexical=${lexicalRisk.toFixed(3)}, combined=${combinedRisk.toFixed(3)}]`;
  }

  // Prepend early-exit note to explanation if triggered
  if (earlyExitTriggered) {
    explanation = `⚡ EARLY BLOCK: ${earlyExitReason}. ` + explanation;
  }

  // Add trusted domain reduction note
  if (trustedReduction > 0.001) {
    explanation += ` [Trusted domain risk reduction: -${(trustedReduction * 100).toFixed(0)}% (×0.15)]`;
  }

  // Convert to 0-100 integer score for backward compatibility
  const score = Math.round(riskScore * 100);

  const totalSources = headlessBrowser ? sourcesChecked.length + '/10' : sourcesChecked.length + '/9';
  const earlyTag = earlyExitTriggered ? ` ⚡EARLY-EXIT: ${earlyExitReason}` : '';
  const temporalTag = temporalPenalty > 0 ? ` ⏰ATR-penalty:+${temporalPenalty.toFixed(3)}` : (temporalTrust > 0 ? ` 🛡ATR-trust:-${temporalTrust.toFixed(3)}` : '');
  const trustTag = trustedReduction > 0.001 ? ` 🛡️TRUST-×0.15:-${trustedReduction.toFixed(3)}` : '';
  console.log(`[ThreatIntel] URL: ${url} | Risk: ${riskScore.toFixed(4)} (infra=${infraRisk.toFixed(3)} lexical=${lexicalRisk.toFixed(3)}) | Score: ${score}/100 | Status: ${status} | Sources: ${totalSources} — ${sourcesChecked.join(', ')}${allExternalClean ? ' (de-escalated)' : ''}${earlyTag}${temporalTag}${trustTag}`);
  if (allThreats.length > 0) {
    console.log(`[ThreatIntel] Threats found:`, allThreats.map(t => `${t.source}: ${t.type}`).join(', '));
  }
  if (errors.length > 0) {
    console.log(`[ThreatIntel] Errors:`, errors.map(e => `${e.source}: ${e.error}`).join(', '));
  }

  return {
    status,
    score,
    risk_score: riskScore,
    infra_risk: infraRisk,
    lexical_risk: lexicalRisk,
    combined_risk: combinedRisk,
    threats: allThreats,
    sources,
    sourcesChecked,
    errors,
    contributions: calibratedContributions,
    raw_contributions: contributions,
    corroboration_bonus: corroborationBonus,
    temporal_risk: temporalPenalty > 0 ? temporalPenalty : 0,
    temporal_trust: temporalTrust > 0 ? temporalTrust : 0,
    domain_age_days: domainAgeDays,
    deescalated: allExternalClean,
    trusted_domain: isTrustedDomain,
    trusted_reduction: trustedReduction > 0.001 ? trustedReduction : 0,
    earlyExit: earlyExitTriggered ? earlyExitReason : false,
    explanation,
    meta: { url, hostname, timestamp: new Date().toISOString() }
  };
}

module.exports = {
  scanUrlMultiSource,
  checkGoogleSafeBrowsing,
  checkVirusTotal,
  checkURLhaus,
  checkAbuseIPDB,
  checkShodan,
  checkHuggingFace,
  checkURLHeuristics,
  checkDomainAge,
  followRedirectChain,
};
