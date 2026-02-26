/**
 * PhishNet Headless Browser Analysis Module
 * 
 * Uses Puppeteer (headless Chrome) to:
 * 1. Fetch the actual rendered page (catches JS-rendered phishing kits)
 * 2. Analyze DOM for hidden login forms / credential harvesting
 * 3. Detect JavaScript obfuscation patterns
 * 4. Deep redirect chain inspection (JS redirects, meta refreshes)
 * 
 * Falls back gracefully if Chrome is not installed.
 */

const puppeteer = require('puppeteer-core');
const path = require('path');
const fs = require('fs');

const HEADLESS_TIMEOUT = 15000; // 15s max per page
const NAVIGATION_TIMEOUT = 12000;

// Trusted domains — skip headless analysis entirely for these
// (they are legitimate sites whose login forms, cookies, and JS patterns
//  would otherwise trigger false-positive "credential exfiltration" / "cookie manipulation" flags)
const HEADLESS_TRUSTED_DOMAINS = [
  'google.com','facebook.com','amazon.com','apple.com','microsoft.com','paypal.com',
  'netflix.com','twitter.com','x.com','instagram.com','linkedin.com','github.com',
  'stackoverflow.com','youtube.com','wikipedia.org','reddit.com','yahoo.com','bing.com',
  'dropbox.com','icloud.com','outlook.com','office.com','live.com','replit.com',
  'npmjs.com','golang.org','python.org','mozilla.org','w3.org','cloudflare.com',
  'amazonaws.com','azure.com','heroku.com','vercel.app','netlify.app',
  'whatsapp.com','telegram.org','discord.com','steampowered.com','spotify.com',
  'twitch.tv','zoom.us','slack.com','notion.so','figma.com','canva.com',
  'appspot.com','googleapis.com','gstatic.com','cdn.jsdelivr.net',
  'chase.com','wellsfargo.com','bankofamerica.com','citi.com',
  'ebay.com','walmart.com','target.com','bestbuy.com',
  'adobe.com','salesforce.com','oracle.com','ibm.com',
  'localhost','127.0.0.1','[::1]','0.0.0.0',
];

function isHeadlessTrusted(url) {
  try {
    const hostname = new URL(url).hostname.toLowerCase().replace(/^www\./, '');
    return HEADLESS_TRUSTED_DOMAINS.some(td => hostname === td || hostname.endsWith('.' + td));
  } catch (_) {
    return false;
  }
}

// ─────────────────────────────────────────────
// Chrome executable discovery
// ─────────────────────────────────────────────
function findChrome() {
  const candidates = process.platform === 'win32'
    ? [
        process.env.CHROME_PATH,
        'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
        'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
        path.join(process.env.LOCALAPPDATA || '', 'Google\\Chrome\\Application\\chrome.exe'),
        'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe',
        'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
      ]
    : process.platform === 'darwin'
    ? [
        process.env.CHROME_PATH,
        '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
        '/Applications/Chromium.app/Contents/MacOS/Chromium',
      ]
    : [
        process.env.CHROME_PATH,
        '/usr/bin/google-chrome',
        '/usr/bin/google-chrome-stable',
        '/usr/bin/chromium',
        '/usr/bin/chromium-browser',
        '/snap/bin/chromium',
      ];

  for (const p of candidates) {
    if (p && fs.existsSync(p)) return p;
  }
  return null;
}

let _browserInstance = null;
let _browserLastUsed = 0;
const BROWSER_IDLE_TIMEOUT = 60000; // close browser after 60s idle

async function getBrowser() {
  if (_browserInstance && _browserInstance.isConnected()) {
    _browserLastUsed = Date.now();
    return _browserInstance;
  }

  const executablePath = findChrome();
  if (!executablePath) {
    throw new Error('No Chrome/Chromium installation found. Set CHROME_PATH env variable.');
  }

  _browserInstance = await puppeteer.launch({
    executablePath,
    headless: 'new',
    args: [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--disable-dev-shm-usage',
      '--disable-gpu',
      '--disable-extensions',
      '--disable-background-networking',
      '--disable-default-apps',
      '--disable-sync',
      '--no-first-run',
      '--single-process',
      '--disable-web-security',  // Allow cross-origin for analysis
    ],
    timeout: 10000,
  });

  _browserLastUsed = Date.now();

  // Auto-close browser after idle period
  const idleCheck = setInterval(() => {
    if (Date.now() - _browserLastUsed > BROWSER_IDLE_TIMEOUT && _browserInstance) {
      _browserInstance.close().catch(() => {});
      _browserInstance = null;
      clearInterval(idleCheck);
    }
  }, 15000);

  return _browserInstance;
}


// ─────────────────────────────────────────────
// Main analysis function
// ─────────────────────────────────────────────

/**
 * Perform deep page analysis using headless browser.
 * 
 * @param {string} url - URL to analyze
 * @returns {object} Analysis results with threats array
 */
async function analyzeWithHeadlessBrowser(url) {
  const result = {
    source: 'Headless Browser Analysis',
    safe: true,
    threats: [],
    hiddenForms: [],
    jsObfuscation: [],
    jsRedirects: [],
    pageMetrics: {},
    available: true,
    raw: {}
  };

  // NOTE: No trusted-domain skip — headless analysis runs on ALL URLs.
  // DOM behavior (hidden forms, credential exfiltration, JS obfuscation) must be
  // evaluated even on trusted domains to detect compromised legitimate sites.
  // The trusted-domain risk reduction is applied at the scoring layer instead.

  let browser, page;
  try {
    browser = await getBrowser();
    page = await browser.newPage();

    // Block unnecessary resources to speed up analysis
    await page.setRequestInterception(true);
    const blockedTypes = ['image', 'media', 'font', 'stylesheet'];
    const networkRequests = [];

    page.on('request', (req) => {
      if (blockedTypes.includes(req.resourceType())) {
        req.abort();
      } else {
        networkRequests.push({
          url: req.url(),
          type: req.resourceType(),
          method: req.method(),
        });
        req.continue();
      }
    });

    // Track JS-initiated navigations
    const jsNavigations = [];
    page.on('framenavigated', (frame) => {
      if (frame === page.mainFrame()) {
        jsNavigations.push(frame.url());
      }
    });

    // Set realistic viewport and user agent
    await page.setViewport({ width: 1366, height: 768 });
    await page.setUserAgent(
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    );

    // Navigate with timeout
    const response = await page.goto(url, {
      waitUntil: 'networkidle2',
      timeout: NAVIGATION_TIMEOUT,
    });

    const finalUrl = page.url();
    const statusCode = response ? response.status() : 0;

    result.pageMetrics = {
      finalUrl,
      statusCode,
      jsNavigations: jsNavigations.length,
      networkRequests: networkRequests.length,
    };

    // ── 1. Hidden Login Form Detection ──
    const formAnalysis = await analyzeFormsInPage(page);
    result.hiddenForms = formAnalysis.hiddenForms;
    if (formAnalysis.threats.length > 0) {
      result.threats.push(...formAnalysis.threats);
    }

    // ── 2. JavaScript Obfuscation Detection ──
    const jsAnalysis = await analyzeJavaScript(page);
    result.jsObfuscation = jsAnalysis.indicators;
    if (jsAnalysis.threats.length > 0) {
      result.threats.push(...jsAnalysis.threats);
    }

    // ── 3. JS Redirect Chain Detection ──
    if (jsNavigations.length > 1) {
      result.jsRedirects = jsNavigations;
      // Check if JS redirected to a different domain (ignore www prefix differences)
      try {
        const origHost = new URL(url).hostname.replace(/^www\./, '');
        const finalHost = new URL(finalUrl).hostname.replace(/^www\./, '');
        if (origHost !== finalHost) {
          result.threats.push({
            source: 'Headless Browser Analysis',
            type: 'JS_REDIRECT_CROSS_DOMAIN',
            detail: `JavaScript redirected from ${origHost} to ${finalHost} — hidden redirect`,
          });
        }
      } catch (_) {}
    }

    // ── 4. Meta refresh detection ──
    const metaRefresh = await page.evaluate(() => {
      const meta = document.querySelector('meta[http-equiv="refresh"]');
      return meta ? meta.getAttribute('content') : null;
    });
    if (metaRefresh) {
      result.threats.push({
        source: 'Headless Browser Analysis',
        type: 'META_REFRESH_REDIRECT',
        detail: `Page uses meta refresh redirect: "${metaRefresh.substring(0, 100)}"`,
      });
    }

    // ── 5. Suspicious page content markers ──
    const pageContent = await page.evaluate(() => {
      const title = document.title || '';
      const bodyText = (document.body?.innerText || '').substring(0, 5000);
      return { title, bodyText };
    });

    // Check for mimicking well-known brands in page title
    const brandKeywords = [
      'paypal', 'chase', 'wells fargo', 'bank of america', 'amazon', 'apple',
      'microsoft', 'google', 'facebook', 'netflix', 'instagram', 'linkedin',
    ];
    const titleLower = (pageContent.title || '').toLowerCase();
    try {
      const pageHost = new URL(finalUrl).hostname;
      for (const brand of brandKeywords) {
        if (titleLower.includes(brand) && !pageHost.includes(brand.replace(/\s/g, ''))) {
          result.threats.push({
            source: 'Headless Browser Analysis',
            type: 'BRAND_IMPERSONATION_TITLE',
            detail: `Page title contains "${brand}" but domain is ${pageHost}`,
          });
          break; // one is enough
        }
      }
    } catch (_) {}

    result.safe = result.threats.length === 0;

  } catch (err) {
    if (err.message.includes('No Chrome') || err.message.includes('CHROME_PATH')) {
      result.available = false;
      result.raw.error = 'Chrome not found — headless analysis unavailable';
    } else {
      result.raw.error = err.message;
    }
  } finally {
    if (page) {
      try { await page.close(); } catch (_) {}
    }
  }

  return result;
}


// ─────────────────────────────────────────────
// DOM Analysis — Hidden Login Forms
// ─────────────────────────────────────────────

async function analyzeFormsInPage(page) {
  const threats = [];
  const hiddenForms = [];

  const formsData = await page.evaluate(() => {
    const forms = Array.from(document.querySelectorAll('form'));
    return forms.map((form, idx) => {
      const rect = form.getBoundingClientRect();
      const style = window.getComputedStyle(form);
      const inputs = Array.from(form.querySelectorAll('input'));

      const inputDetails = inputs.map(input => {
        const iRect = input.getBoundingClientRect();
        const iStyle = window.getComputedStyle(input);
        return {
          type: input.type,
          name: input.name || input.id || '',
          autocomplete: input.autocomplete || '',
          isHidden: iStyle.display === 'none' || iStyle.visibility === 'hidden'
            || iRect.width === 0 || iRect.height === 0
            || parseFloat(iStyle.opacity) === 0,
          hasValue: !!input.value,
        };
      });

      return {
        index: idx,
        action: form.action || '',
        method: (form.method || 'GET').toUpperCase(),
        // Hidden form detection criteria
        isHidden: style.display === 'none' || style.visibility === 'hidden'
          || rect.width === 0 || rect.height === 0
          || parseFloat(style.opacity) === 0
          || rect.top < -1000 || rect.left < -1000,
        hasPasswordInput: inputs.some(i => i.type === 'password'),
        hasEmailInput: inputs.some(i => i.type === 'email' || i.name.match(/email|user|login/i)),
        hasCreditCardInput: inputs.some(i =>
          (i.name + i.autocomplete).match(/card|cc[-_]?num|cvv|cvc|expir/i)
        ),
        hasSSNInput: inputs.some(i => i.name.match(/ssn|social.*security|tax.*id/i)),
        inputCount: inputs.length,
        inputs: inputDetails,
        // Check if form posts to a different domain
        crossOriginAction: false, // will be computed below
      };
    });
  });

  // Analyze the page's URL to detect cross-origin form actions
  const pageUrl = page.url();
  let pageHost = '';
  try { pageHost = new URL(pageUrl).hostname; } catch (_) {}

  for (const form of formsData) {
    // Check cross-origin form action
    if (form.action) {
      try {
        const actionHost = new URL(form.action).hostname;
        if (actionHost && pageHost && actionHost !== pageHost) {
          form.crossOriginAction = true;
        }
      } catch (_) {}
    }

    // Credential harvesting: hidden form with password/email inputs
    if (form.isHidden && (form.hasPasswordInput || form.hasEmailInput)) {
      hiddenForms.push({
        index: form.index,
        type: 'hidden_credential_form',
        inputs: form.inputs.filter(i => ['password', 'email', 'text'].includes(i.type)),
      });
      threats.push({
        source: 'Headless Browser Analysis',
        type: 'HIDDEN_LOGIN_FORM',
        detail: `Hidden form #${form.index} contains ${form.hasPasswordInput ? 'password' : 'email/username'} input — credential harvesting indicator`,
      });
    }

    // Credit card / SSN harvesting
    if (form.hasCreditCardInput) {
      threats.push({
        source: 'Headless Browser Analysis',
        type: 'CREDIT_CARD_FORM',
        detail: `Form #${form.index} contains credit card input fields`,
      });
    }
    if (form.hasSSNInput) {
      threats.push({
        source: 'Headless Browser Analysis',
        type: 'SSN_FORM',
        detail: `Form #${form.index} contains Social Security Number input fields`,
      });
    }

    // Cross-origin POST form with credentials
    if (form.crossOriginAction && form.method === 'POST' && (form.hasPasswordInput || form.hasEmailInput)) {
      threats.push({
        source: 'Headless Browser Analysis',
        type: 'CROSS_ORIGIN_CREDENTIAL_FORM',
        detail: `Form POSTs credentials to a different domain: ${form.action}`,
      });
    }

    // Phishing kit pattern: visible form on a non-brand domain
    if (!form.isHidden && form.hasPasswordInput && form.hasEmailInput && form.method === 'POST') {
      // This is a login form — could be legitimate, but flag if domain is suspicious
      hiddenForms.push({
        index: form.index,
        type: 'visible_login_form',
        inputs: form.inputs.filter(i => ['password', 'email', 'text'].includes(i.type)),
      });
    }
  }

  return { threats, hiddenForms };
}


// ─────────────────────────────────────────────
// JavaScript Obfuscation Detection
// ─────────────────────────────────────────────

async function analyzeJavaScript(page) {
  const threats = [];
  const indicators = [];

  const jsAnalysis = await page.evaluate(() => {
    const scripts = Array.from(document.querySelectorAll('script'));
    const results = {
      totalScripts: scripts.length,
      inlineScripts: 0,
      obfuscationIndicators: [],
      suspiciousAPIs: [],
      externalScriptDomains: [],
    };

    scripts.forEach((script, idx) => {
      const src = script.src || '';
      const content = script.textContent || '';

      if (!src && content.length > 0) {
        results.inlineScripts++;
        const contentLower = content.toLowerCase();

        // ── Obfuscation pattern detection ──

        // 1. eval() usage (common in obfuscated phishing kits)
        const evalCount = (content.match(/\beval\s*\(/g) || []).length;
        if (evalCount > 0) {
          results.obfuscationIndicators.push({
            type: 'EVAL_USAGE',
            detail: `Script #${idx} uses eval() ${evalCount} time(s)`,
            count: evalCount,
          });
        }

        // 2. document.write — older technique for injecting content
        const docWriteCount = (content.match(/document\.write\s*\(/g) || []).length;
        if (docWriteCount > 0) {
          results.obfuscationIndicators.push({
            type: 'DOCUMENT_WRITE',
            detail: `Script #${idx} uses document.write() ${docWriteCount} time(s)`,
            count: docWriteCount,
          });
        }

        // 3. String.fromCharCode chains (hiding strings as char codes)
        const fromCharCodeCount = (content.match(/String\.fromCharCode/gi) || []).length;
        if (fromCharCodeCount >= 3) {
          results.obfuscationIndicators.push({
            type: 'CHARCODE_OBFUSCATION',
            detail: `Script #${idx} uses String.fromCharCode ${fromCharCodeCount} times — hiding strings`,
            count: fromCharCodeCount,
          });
        }

        // 4. atob/btoa (Base64 decode/encode)
        const atobCount = (content.match(/\batob\s*\(/g) || []).length;
        if (atobCount >= 2) {
          results.obfuscationIndicators.push({
            type: 'BASE64_DECODE',
            detail: `Script #${idx} decodes Base64 strings ${atobCount} times`,
            count: atobCount,
          });
        }

        // 5. Hex escape sequences (\x41\x42\x43...)
        // Legitimate minified JS (Google, Facebook, etc.) routinely has 200+ hex escapes
        // for i18n, emoji, and character encoding. Use both absolute threshold (500+)
        // AND density ratio (>8% of script chars) to avoid false positives.
        const hexEscapes = (content.match(/\\x[0-9a-f]{2}/gi) || []).length;
        const hexDensity = content.length > 0 ? (hexEscapes * 4) / content.length : 0;
        if (hexEscapes >= 500 || (hexEscapes >= 100 && hexDensity > 0.08)) {
          results.obfuscationIndicators.push({
            type: 'HEX_ESCAPE_OBFUSCATION',
            detail: `Script #${idx} contains ${hexEscapes} hex escape sequences (density: ${(hexDensity*100).toFixed(1)}%)`,
            count: hexEscapes,
          });
        }

        // 6. Unicode escape sequences (\u0041...)
        const unicodeEscapes = (content.match(/\\u[0-9a-f]{4}/gi) || []).length;
        if (unicodeEscapes >= 50) {
          results.obfuscationIndicators.push({
            type: 'UNICODE_ESCAPE_OBFUSCATION',
            detail: `Script #${idx} contains ${unicodeEscapes} unicode escapes`,
            count: unicodeEscapes,
          });
        }

        // 7. Very long single-line code (minified/packed/obfuscated)
        const lines = content.split('\n');
        const maxLineLen = Math.max(...lines.map(l => l.length));
        if (maxLineLen > 15000 && results.inlineScripts <= 3) {
          results.obfuscationIndicators.push({
            type: 'PACKED_CODE',
            detail: `Script #${idx} has a ${maxLineLen}-char line — likely packed/obfuscated`,
            count: 1,
          });
        }

        // 8. Array-based string decoding (common obfuscator pattern)
        //    var _0x1234 = ['string1', 'string2', ...]; followed by _0x1234[0]
        if (/var\s+_0x[a-f0-9]+\s*=\s*\[/i.test(content)) {
          results.obfuscationIndicators.push({
            type: 'ARRAY_STRING_OBFUSCATION',
            detail: `Script #${idx} uses array-indexed string obfuscation (_0x pattern)`,
            count: 1,
          });
        }

        // 9. Suspicious API usage — credential stealing
        if (contentLower.includes('navigator.credentials') || contentLower.includes('credential')) {
          results.suspiciousAPIs.push('navigator.credentials');
        }
        if (/\.cookie\s*=/i.test(content)) {
          results.suspiciousAPIs.push('cookie manipulation');
        }
        // Keylogger patterns: key listener + exfiltration in same script
        const hasKeyListener = /addEventListener\s*\(\s*['"]key(down|up|press)['"]/i.test(content);
        const hasExfil = /new\s+XMLHttpRequest|fetch\s*\(|\.send\s*\(/i.test(content) && /password|passwd|credit|card|ssn|login/i.test(content);
        if (hasKeyListener && hasExfil) {
          results.suspiciousAPIs.push('keylogger event listener');
        }
        // Form data exfiltration via fetch/XMLHttpRequest to external domain
        // Require both: (a) network call AND (b) sensitive field names AND
        //               (c) actual value extraction patterns (not just mentioning the word)
        const hasNetworkCall = /new\s+XMLHttpRequest|fetch\s*\(/i.test(content);
        const hasSensitiveAccess = /\.value[^s].*(?:password|passwd|ssn|card)/i.test(content)
                                || /(?:password|passwd|ssn|card).*\.value/i.test(content)
                                || /querySelector.*(?:password|passwd|ssn).*\.value/i.test(content);
        if (hasNetworkCall && hasSensitiveAccess) {
          results.suspiciousAPIs.push('credential exfiltration pattern');
        }
      }

      // Track external script domains
      if (src) {
        try {
          const scriptHost = new URL(src).hostname;
          if (!results.externalScriptDomains.includes(scriptHost)) {
            results.externalScriptDomains.push(scriptHost);
          }
        } catch (_) {}
      }
    });

    return results;
  });

  // Process obfuscation indicators
  // Require 4+ techniques and at least one aggressive pattern to flag as heavy
  const aggressivePatterns = ['ARRAY_STRING_OBFUSCATION', 'CHARCODE_OBFUSCATION', 'EVAL_OBFUSCATION', 'DOCUMENT_WRITE_OBFUSCATION'];
  const hasAggressive = jsAnalysis.obfuscationIndicators.some(i => aggressivePatterns.includes(i.type));
  if (jsAnalysis.obfuscationIndicators.length >= 4 && hasAggressive) {
    const types = jsAnalysis.obfuscationIndicators.map(i => i.type).join(', ');
    threats.push({
      source: 'Headless Browser Analysis',
      type: 'HEAVY_JS_OBFUSCATION',
      detail: `Page uses ${jsAnalysis.obfuscationIndicators.length} obfuscation techniques: ${types}`,
    });
    indicators.push(...jsAnalysis.obfuscationIndicators);
  } else if (jsAnalysis.obfuscationIndicators.length > 0) {
    indicators.push(...jsAnalysis.obfuscationIndicators);
    // Single obfuscation technique is common even in legitimate code (e.g. analytics)
    // Only flag if it's a known aggressive pattern
    // HEX_ESCAPE_OBFUSCATION alone is common in legitimate minified JS — only flag
    // ARRAY_STRING_OBFUSCATION and CHARCODE_OBFUSCATION as solo-aggressive patterns
    const aggressive = jsAnalysis.obfuscationIndicators.filter(i =>
      ['ARRAY_STRING_OBFUSCATION', 'CHARCODE_OBFUSCATION'].includes(i.type)
    );
    if (aggressive.length > 0) {
      threats.push({
        source: 'Headless Browser Analysis',
        type: 'JS_OBFUSCATION',
        detail: `Aggressive JavaScript obfuscation detected: ${aggressive.map(a => a.type).join(', ')}`,
      });
    }
  }

  // Suspicious API usage
  if (jsAnalysis.suspiciousAPIs.length > 0) {
    const unique = [...new Set(jsAnalysis.suspiciousAPIs)];
    if (unique.some(api => ['keylogger event listener', 'credential exfiltration pattern'].includes(api))) {
      threats.push({
        source: 'Headless Browser Analysis',
        type: 'SUSPICIOUS_JS_BEHAVIOR',
        detail: `Suspicious JavaScript behavior: ${unique.join(', ')}`,
      });
    }
    indicators.push({ type: 'SUSPICIOUS_APIS', apis: unique });
  }

  return { threats, indicators, raw: jsAnalysis };
}


// ─────────────────────────────────────────────
// Cleanup
// ─────────────────────────────────────────────
async function closeBrowser() {
  if (_browserInstance) {
    await _browserInstance.close().catch(() => {});
    _browserInstance = null;
  }
}

module.exports = {
  analyzeWithHeadlessBrowser,
  closeBrowser,
  findChrome,
};
