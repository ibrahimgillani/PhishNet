/**
 * PhishNet On-Device Lightweight Pre-Filter
 * ==========================================
 * Runs BEFORE any backend API call to instantly block obvious phishing URLs.
 * 
 * Three detection layers:
 * 1. PUNYCODE / IDN HOMOGRAPH — Detects internationalized domain names
 *    that visually mimic real brands (e.g., xn--pypal-4ve.com → "pаypal.com")
 * 2. ENTROPY ANALYSIS — High-entropy domains suggest randomly generated
 *    phishing/DGA domains. Legitimate domains are human-readable.
 * 3. BRAND-DOMAIN MISMATCH — Detects brand keywords (paypal, microsoft, etc.)
 *    in subdomains/paths when the actual registrable domain doesn't own that brand.
 * 
 * If any check returns HIGH confidence → instant block (no API call needed).
 * If medium signals stack → combined block.
 * Otherwise → pass through to full backend scan.
 * 
 * Zero network calls. Sub-millisecond execution.
 */

// ── Brand → legitimate domain mappings ──
const BRAND_DOMAINS = {
  'paypal':     ['paypal.com', 'paypal.co.uk', 'paypal.me'],
  'apple':      ['apple.com', 'icloud.com', 'appleid.apple.com'],
  'microsoft':  ['microsoft.com', 'live.com', 'outlook.com', 'office.com', 'office365.com', 'microsoftonline.com', 'azure.com', 'windows.com', 'bing.com'],
  'google':     ['google.com', 'google.co.uk', 'google.co.in', 'gmail.com', 'googleapis.com', 'google.cloud', 'youtube.com', 'accounts.google.com', 'goo.gl'],
  'amazon':     ['amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.in', 'aws.amazon.com', 'amazonaws.com'],
  'netflix':    ['netflix.com'],
  'facebook':   ['facebook.com', 'fb.com', 'fb.me', 'meta.com', 'instagram.com'],
  'instagram':  ['instagram.com', 'facebook.com', 'meta.com'],
  'whatsapp':   ['whatsapp.com', 'whatsapp.net', 'meta.com'],
  'twitter':    ['twitter.com', 'x.com', 't.co'],
  'linkedin':   ['linkedin.com'],
  'dropbox':    ['dropbox.com', 'dropboxapi.com'],
  'chase':      ['chase.com', 'jpmorganchase.com'],
  'wellsfargo': ['wellsfargo.com'],
  'bankofamerica': ['bankofamerica.com', 'bofa.com'],
  'citibank':   ['citibank.com', 'citi.com', 'citigroup.com'],
  'usps':       ['usps.com'],
  'fedex':      ['fedex.com'],
  'ups':        ['ups.com'],
  'dhl':        ['dhl.com', 'dhl.de'],
  'steam':      ['steampowered.com', 'steamcommunity.com'],
  'discord':    ['discord.com', 'discord.gg', 'discordapp.com'],
  'github':     ['github.com', 'github.io', 'githubusercontent.com'],
  'coinbase':   ['coinbase.com'],
  'binance':    ['binance.com', 'binance.us'],
  'metamask':   ['metamask.io'],
  'blockchain': ['blockchain.com', 'blockchain.info'],
  'stripe':     ['stripe.com'],
  'spotify':    ['spotify.com'],
  'adobe':      ['adobe.com', 'creativecloud.com'],
  'walmart':    ['walmart.com'],
  'ebay':       ['ebay.com', 'ebay.co.uk'],
  'docusign':   ['docusign.com', 'docusign.net'],
  'yahoo':      ['yahoo.com', 'ymail.com'],
  'aol':        ['aol.com'],
  'att':        ['att.com', 'att.net'],
  'verizon':    ['verizon.com', 'vzw.com'],
  'tmobile':    ['t-mobile.com'],
  'comcast':    ['comcast.com', 'xfinity.com'],
  'hsbc':       ['hsbc.com', 'hsbc.co.uk'],
  'barclays':   ['barclays.co.uk', 'barclays.com'],
  'santander':  ['santander.com', 'santander.co.uk'],
  'irs':        ['irs.gov'],
  'hmrc':       ['hmrc.gov.uk', 'gov.uk'],
};

// Suspicious phishing keywords in paths/subdomains
const PHISHING_PATH_KEYWORDS = [
  'login', 'signin', 'sign-in', 'log-in', 'verify', 'verification',
  'secure', 'security', 'account', 'update', 'confirm', 'suspend',
  'unlock', 'restore', 'authenticate', 'wallet', 'billing', 'payment',
  'password', 'credential', 'validate', 'recover'
];

/**
 * Extract the registrable domain (eTLD+1) from a hostname.
 * Handles common multi-part TLDs like co.uk, com.au, etc.
 */
function extractRegistrableDomain(hostname) {
  const parts = hostname.replace(/^www\./, '').split('.');
  const knownSecondLevel = ['co', 'com', 'org', 'net', 'gov', 'edu', 'ac', 'or', 'ne'];
  if (parts.length >= 3 && knownSecondLevel.includes(parts[parts.length - 2])) {
    return parts.slice(-3).join('.');
  }
  return parts.slice(-2).join('.');
}

/**
 * 1. PUNYCODE / IDN HOMOGRAPH DETECTION
 *    Detects xn-- encoded domains (internationalized domain names).
 *    Attackers use Cyrillic/Greek lookalikes to impersonate brands.
 *    e.g., xn--pypal-4ve.com renders as "pаypal.com" with Cyrillic 'а'
 */
function checkPunycode(hostname) {
  const flags = [];
  const labels = hostname.split('.');

  for (const label of labels) {
    if (label.startsWith('xn--')) {
      flags.push({
        type: 'PUNYCODE_IDN',
        severity: 'high',
        detail: `Internationalized domain label "${label}" detected — possible homograph attack`
      });
    }
  }

  // Also detect mixed-script indicators in non-punycode form
  // (browsers may auto-decode punycode in the URL bar)
  const domainNoTld = labels.slice(0, -1).join('.');
  // Check for mixing of Latin with Cyrillic/Greek lookalikes in raw form
  // These Unicode ranges contain characters visually identical to Latin letters
  if (/[\u0400-\u04FF]/.test(domainNoTld) || /[\u0370-\u03FF]/.test(domainNoTld)) {
    flags.push({
      type: 'MIXED_SCRIPT_DOMAIN',
      severity: 'high',
      detail: 'Domain contains Cyrillic or Greek characters — likely homograph attack'
    });
  }

  return flags;
}

/**
 * 2. ENTROPY ANALYSIS
 *    Measures Shannon entropy of domain labels. Random/DGA domains
 *    have entropy > 3.5 bits/char. Human-readable domains are typically < 3.0.
 *    
 *    Examples:
 *      "google"    → 2.25 (low, human-readable)
 *      "facebook"  → 2.75 (low)
 *      "a3xk9q2m"  → 3.00 (borderline)
 *      "r7f2kx9p3"  → 3.32 (high, likely DGA)
 *      "a1b2c3d4e5f6" → 3.58 (very high, auto-generated)
 */
function shannonEntropy(str) {
  if (!str || str.length === 0) return 0;
  const freq = {};
  for (const ch of str) {
    freq[ch] = (freq[ch] || 0) + 1;
  }
  let entropy = 0;
  const len = str.length;
  for (const ch in freq) {
    const p = freq[ch] / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function checkEntropy(hostname) {
  const flags = [];
  const registrable = extractRegistrableDomain(hostname);
  const domainName = registrable.split('.')[0]; // Just the domain label (no TLD)

  const entropy = shannonEntropy(domainName);

  // Very high entropy + long domain = DGA/randomly generated
  if (entropy > 3.8 && domainName.length >= 8) {
    flags.push({
      type: 'ENTROPY_VERY_HIGH',
      severity: 'high',
      detail: `Domain "${domainName}" has very high entropy (${entropy.toFixed(2)} bits/char, ${domainName.length} chars) — likely auto-generated/DGA`
    });
  } else if (entropy > 3.5 && domainName.length >= 10) {
    flags.push({
      type: 'ENTROPY_HIGH',
      severity: 'medium',
      detail: `Domain "${domainName}" has high entropy (${entropy.toFixed(2)} bits/char, ${domainName.length} chars) — possibly randomized`
    });
  }

  // Also check subdomain labels for high entropy (attackers put random subdomains)
  const hostClean = hostname.replace(/^www\./, '');
  const subdomainPart = hostClean.replace(registrable, '').replace(/\.$/, '');
  if (subdomainPart) {
    const subLabels = subdomainPart.split('.').filter(s => s.length > 0);
    for (const sub of subLabels) {
      const subEntropy = shannonEntropy(sub);
      if (subEntropy > 3.5 && sub.length >= 8) {
        flags.push({
          type: 'ENTROPY_HIGH_SUBDOMAIN',
          severity: 'medium',
          detail: `Subdomain "${sub}" has high entropy (${subEntropy.toFixed(2)} bits/char) — possibly randomized`
        });
      }
    }
  }

  return flags;
}

/**
 * 3. BRAND-DOMAIN MISMATCH
 *    Detects brand keywords appearing in subdomains, paths, or query strings
 *    when the registrable domain is NOT the legitimate owner of that brand.
 *    
 *    e.g., "paypal-login.evil.com" → brand "paypal" in subdomain, but domain is "evil.com"
 *          "evil.com/paypal/login" → brand "paypal" in path, domain is "evil.com"
 */
function checkBrandMismatch(hostname, pathname) {
  const flags = [];
  const registrable = extractRegistrableDomain(hostname);
  const hostClean = hostname.replace(/^www\./, '');

  // Build the text to search for brand keywords:
  // subdomain part + path + the registrable domain name itself
  const subdomainPart = hostClean.replace(registrable, '').replace(/\.$/, '');
  const searchText = (subdomainPart + ' ' + registrable.split('.')[0] + ' ' + (pathname || '')).toLowerCase();

  const matchedBrands = [];

  for (const [brand, legitimateDomains] of Object.entries(BRAND_DOMAINS)) {
    // Skip very short brand names to avoid false positives (e.g., "ups" in "updates")
    if (brand.length < 4) continue;

    // Check if brand keyword appears in the URL components
    const brandRegex = new RegExp(`(?:^|[^a-z])${brand}(?:[^a-z]|$)`, 'i');
    const inSubdomain = brandRegex.test(subdomainPart);
    const inPath = brandRegex.test(pathname || '');
    const inDomainName = brandRegex.test(registrable.split('.')[0]);

    if (inSubdomain || inPath || inDomainName) {
      // Check if the registrable domain is actually owned by this brand
      const isLegitimate = legitimateDomains.some(ld => {
        return registrable === ld || registrable.endsWith('.' + ld);
      });

      if (!isLegitimate) {
        const location = inSubdomain ? 'subdomain' : (inDomainName ? 'domain name' : 'path');
        
        // Higher severity if combined with phishing path keywords
        const hasPhishingKeyword = PHISHING_PATH_KEYWORDS.some(kw => 
          (pathname || '').toLowerCase().includes(kw) || subdomainPart.toLowerCase().includes(kw)
        );

        matchedBrands.push({
          brand,
          location,
          hasPhishingKeyword,
          severity: hasPhishingKeyword ? 'high' : 'medium'
        });
      }
    }
  }

  for (const match of matchedBrands) {
    const phishNote = match.hasPhishingKeyword ? ' + phishing keywords in URL' : '';
    flags.push({
      type: 'BRAND_DOMAIN_MISMATCH',
      severity: match.severity,
      detail: `Brand "${match.brand}" found in ${match.location} but domain "${registrable}" is not a legitimate ${match.brand} domain${phishNote}`
    });
  }

  return flags;
}

/**
 * MAIN PRE-FILTER FUNCTION
 * Runs all three checks and decides: BLOCK, WARN, or PASS
 * 
 * Returns:
 *   { action: 'BLOCK', score: 95, reason: '...', flags: [...] }  → instant block
 *   { action: 'PASS', score: 0, flags: [] }                       → continue to backend
 * 
 * Blocking thresholds:
 *   - Any single HIGH severity flag → BLOCK
 *   - 2+ MEDIUM severity flags → BLOCK (stacking)
 *   - 1 MEDIUM flag → PASS (let backend decide)
 */
function preFilterUrl(url) {
  try {
    const parsed = new URL(url);
    const hostname = parsed.hostname.toLowerCase();
    const pathname = parsed.pathname;

    // Skip internal/local URLs
    if (['localhost', '127.0.0.1', '[::1]', '0.0.0.0'].includes(hostname)) {
      return { action: 'PASS', score: 0, flags: [], reason: 'Local URL' };
    }

    // Run all three checks
    const punycodeFlags = checkPunycode(hostname);
    const entropyFlags = checkEntropy(hostname);
    const brandFlags = checkBrandMismatch(hostname, pathname);

    const allFlags = [...punycodeFlags, ...entropyFlags, ...brandFlags];

    if (allFlags.length === 0) {
      return { action: 'PASS', score: 0, flags: [], reason: null };
    }

    const highFlags = allFlags.filter(f => f.severity === 'high');
    const mediumFlags = allFlags.filter(f => f.severity === 'medium');

    // Decision logic
    if (highFlags.length > 0) {
      // Any HIGH severity → instant block
      const score = Math.min(98, 80 + highFlags.length * 6);
      const reasons = highFlags.map(f => f.detail).join('; ');
      return {
        action: 'BLOCK',
        score,
        status: 'MALICIOUS',
        flags: allFlags,
        reason: `⚡ PRE-FILTER BLOCK: ${reasons}`,
        explanation: `On-device pre-filter detected high-confidence phishing signals before backend scan. ${allFlags.map(f => f.detail).join('. ')}.`
      };
    }

    if (mediumFlags.length >= 2) {
      // 2+ medium signals stacking → block
      const score = Math.min(90, 60 + mediumFlags.length * 10);
      const reasons = mediumFlags.map(f => f.detail).join('; ');
      return {
        action: 'BLOCK',
        score,
        status: mediumFlags.length >= 3 ? 'MALICIOUS' : 'SUSPICIOUS',
        flags: allFlags,
        reason: `⚡ PRE-FILTER BLOCK: ${reasons}`,
        explanation: `On-device pre-filter detected multiple suspicious signals. ${allFlags.map(f => f.detail).join('. ')}.`
      };
    }

    // Single medium flag → pass through to backend for full analysis
    return {
      action: 'PASS',
      score: 0,
      flags: allFlags,
      reason: null,
      preFilterHints: allFlags
    };
  } catch (e) {
    // If URL can't even be parsed, let backend handle it
    return { action: 'PASS', score: 0, flags: [], reason: null };
  }
}

// Make available globally in all JavaScript contexts:
// - Browser <script> tags: window.PhishNetPreFilter
// - Extension service worker importScripts: globalThis.preFilterUrl
// - Node.js CJS: module.exports (when available)
(function(root) {
  const exports = { preFilterUrl, checkPunycode, checkEntropy, checkBrandMismatch, shannonEntropy, extractRegistrableDomain, BRAND_DOMAINS };

  // Browser <script> tag
  if (typeof window !== 'undefined') {
    window.PhishNetPreFilter = exports;
  }

  // Service worker / globalThis (extension importScripts)
  if (typeof self !== 'undefined' && typeof window === 'undefined') {
    // We're in a service worker or Web Worker
    self.preFilterUrl = preFilterUrl;
    self.PhishNetPreFilter = exports;
  }

  // Node.js CJS
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = exports;
  }

  // globalThis fallback
  if (typeof globalThis !== 'undefined') {
    globalThis.PhishNetPreFilter = exports;
    globalThis.preFilterUrl = preFilterUrl;
  }
})(typeof globalThis !== 'undefined' ? globalThis : typeof self !== 'undefined' ? self : this);
