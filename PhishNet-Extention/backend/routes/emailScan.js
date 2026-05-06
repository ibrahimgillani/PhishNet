/**
 * PhishNet Email Analysis Route
 * POST /api/v1/emails/scan
 * 
 * Performs deep email scanning:
 *  Phase 1 — Header Analysis (IP, DNS, DMARC, SPF, DKIM, sender/receiver, routing)
 *  Phase 2 — Body/Structure Analysis (ML + heuristic phishing detection)
 *  Phase 3 — Combined Verdict
 */

const express = require('express');
const dns = require('dns');
const https = require('https');
const { promisify } = require('util');
const router = express.Router();
const { verifyAccessToken } = require('../utils/jwt');
const URLCheckHistory = require('../models/URLCheckHistory');
const { extractAndDecodeQRCodes } = require('../utils/qr-scanner');
const { scanUrlMultiSource } = require('../utils/threatIntel');

// ── DNS-over-HTTPS (DoH) for TXT lookups ──
// Traditional DNS (port 53) times out on some networks. DoH uses HTTPS (port 443).
// Uses Cloudflare 1.1.1.1 directly by IP (hostname-based DoH was being reset).
function resolveTxtDoH(domain) {
  return new Promise((resolve, reject) => {
    const opts = {
      hostname: '1.1.1.1',
      path: `/dns-query?name=${encodeURIComponent(domain)}&type=TXT`,
      headers: { Accept: 'application/dns-json' },
      timeout: 5000,
      rejectUnauthorized: false
    };
    const req = https.get(opts, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          if (json.Status === 0 && json.Answer) {
            const records = json.Answer
              .filter(a => a.type === 16)
              .map(a => {
                // Strip escaped quotes from DoH JSON: \"v=spf1...\" → v=spf1...
                const clean = a.data.replace(/^\\?"|\\?"$/g, '').replace(/\\"/g, '"');
                return [clean];
              });
            if (records.length > 0) return resolve(records);
          }
          const err = new Error('ENOTFOUND');
          err.code = 'ENOTFOUND';
          reject(err);
        } catch (e) { reject(e); }
      });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); const e = new Error('ETIMEOUT'); e.code = 'ETIMEOUT'; reject(e); });
  });
}
const resolveTxt = resolveTxtDoH;

// ── DNS-over-HTTPS for MX lookups (system DNS also times out for some domains) ──
function resolveMxDoH(domain) {
  return new Promise((resolve, reject) => {
    const opts = {
      hostname: '1.1.1.1',
      path: `/dns-query?name=${encodeURIComponent(domain)}&type=MX`,
      headers: { Accept: 'application/dns-json' },
      timeout: 5000,
      rejectUnauthorized: false
    };
    const req = https.get(opts, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          if (json.Status === 0 && json.Answer) {
            const records = json.Answer
              .filter(a => a.type === 15) // MX record type
              .map(a => {
                const parts = a.data.split(/\s+/);
                return { priority: parseInt(parts[0]) || 10, exchange: (parts[1] || '').replace(/\.$/, '') };
              });
            return resolve(records);
          }
          resolve([]);
        } catch (e) { reject(e); }
      });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); const e = new Error('ETIMEOUT'); e.code = 'ETIMEOUT'; reject(e); });
  });
}

// Try system DNS first for MX (fast), fall back to DoH if it fails
async function resolveMxWithFallback(domain) {
  try {
    return await promisify(dns.resolveMx)(domain);
  } catch {
    return resolveMxDoH(domain);
  }
}
const resolveMx = resolveMxWithFallback;

const resolve4   = promisify(dns.resolve4);
const reverse    = promisify(dns.reverse);


// ════════════════════════════════════════════════════════════════
//  TRUSTED SENDER DOMAINS
// ════════════════════════════════════════════════════════════════
const TRUSTED_SENDER_DOMAINS = new Set([
  'google.com', 'gmail.com', 'googlemail.com',
  'microsoft.com', 'outlook.com', 'hotmail.com', 'live.com', 'office.com',
  'yahoo.com', 'ymail.com',
  'apple.com', 'icloud.com', 'me.com',
  'amazon.com', 'amazonses.com',
  'facebook.com', 'fb.com', 'meta.com',
  'linkedin.com', 'limail.com',
  'twitter.com', 'x.com',
  'github.com',
  'paypal.com', 'paypal.me',
  'chase.com', 'bankofamerica.com', 'wellsfargo.com', 'citibank.com',
  'dropbox.com', 'dropboxmail.com',
  'slack.com', 'salesforce.com',
  'netflix.com', 'spotify.com', 'uber.com', 'airbnb.com',
  'adobe.com', 'zoom.us',
  'nhs.uk', 'gov.uk',
  'bsky.social', 'bsky.app',
  'discord.com', 'discordapp.com',
  'reddit.com', 'redditmail.com',
  'twitch.tv',
  'telegram.org',
  'whatsapp.com',
  'signal.org',
  'notion.so', 'notion.com',
  'figma.com',
  'stripe.com',
  'shopify.com',
  'canva.com',
  'trello.com', 'atlassian.com',
  // Pakistani banking, telecom & fintech
  'telenorbank.pk', 'easypaisa.com.pk',
  'jazzcash.com.pk', 'mobilinkbank.com',
  'hbl.com', 'hbl.com.pk',
  'ubl.com.pk',
  'meezanbank.com',
  'bankislami.com.pk',
  'alfalahbank.com',
  'scb.com.pk', 'sc.com',
  'nayapay.com',
  'sadapay.pk',
  // Indian banking & fintech
  'hdfcbank.com', 'icicibank.com', 'sbi.co.in',
  'paytm.com', 'phonepe.com', 'razorpay.com',
  // International banking
  'hsbc.com', 'barclays.com', 'barclays.co.uk',
  'ing.com', 'revolut.com', 'wise.com',
]);

const INSTITUTIONAL_TLDS = [/\.edu$/i, /\.ac\.[a-z]{2}$/i, /\.gov(\.[a-z]{2})?$/i, /\.mil$/i];

const SUSPICIOUS_TLDS = new Set(['.xyz', '.top', '.click', '.link', '.info', '.online', '.site', '.club', '.work', '.live', '.gq', '.ml', '.cf', '.tk', '.ga', '.buzz', '.icu']);

const BRAND_DOMAINS = {
  paypal:    ['paypal.com', 'paypal.me'],
  amazon:    ['amazon.com', 'amazon.co.uk', 'amazonses.com'],
  google:    ['google.com', 'gmail.com', 'googlemail.com'],
  microsoft: ['microsoft.com', 'outlook.com', 'live.com', 'office.com'],
  apple:     ['apple.com', 'icloud.com', 'me.com'],
  netflix:   ['netflix.com'],
  facebook:  ['facebook.com', 'fb.com', 'meta.com'],
  chase:     ['chase.com', 'jpmchase.com'],
  linkedin:  ['linkedin.com'],
  dropbox:   ['dropbox.com'],
  instagram: ['instagram.com'],
  twitter:   ['twitter.com', 'x.com'],
  easypaisa: ['telenorbank.pk', 'easypaisa.com.pk'],
  jazzcash:  ['jazzcash.com.pk', 'mobilinkbank.com'],
  hbl:       ['hbl.com', 'hbl.com.pk'],
  meezanbank:['meezanbank.com'],
  paytm:     ['paytm.com'],
  wise:      ['wise.com'],
  revolut:   ['revolut.com'],
};

// ════════════════════════════════════════════════════════════════
//  PHASE 1: DEEP HEADER ANALYSIS
// ════════════════════════════════════════════════════════════════

function parseHeaders(rawHeaders) {
  const result = {
    from: null,
    fromName: null,
    fromDomain: null,
    to: null,
    toDomain: null,
    replyTo: null,
    replyToDomain: null,
    returnPath: null,
    returnPathDomain: null,
    subject: null,
    date: null,
    messageId: null,
    xMailer: null,
    xOriginalFrom: null,
    contentType: null,
    mimeVersion: null,
    receivedChain: [],
    authenticationResults: [],
    spf: { result: null, detail: null },
    dkim: { result: null, detail: null },
    dmarc: { result: null, detail: null },
    arc: { result: null },
    listUnsubscribe: null,
    precedence: null,
    xHeaders: {},
    rawIPs: [],
    allHeaders: {}
  };

  if (!rawHeaders || typeof rawHeaders !== 'string') return result;

  // Unfold continuation lines (lines starting with whitespace are continuations)
  const unfolded = rawHeaders.replace(/\r?\n([ \t]+)/g, ' ');
  const lines = unfolded.split(/\r?\n/);

  const emailRegex = /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/;
  const ipv4Regex = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g;

  for (const line of lines) {
    if (!line.includes(':')) continue;
    const colonIdx = line.indexOf(':');
    const rawName = line.substring(0, colonIdx).trim().toLowerCase();
    const value = line.substring(colonIdx + 1).trim();

    // Normalize common pasted formats from users
    let name = rawName;
    if (name === 'sender email' || name === 'from email' || name === 'sender') name = 'from';
    if (name === 'receiver email' || name === 'to email' || name === 'receiver') name = 'to';

    result.allHeaders[name] = result.allHeaders[name]
      ? (Array.isArray(result.allHeaders[name]) ? [...result.allHeaders[name], value] : [result.allHeaders[name], value])
      : value;

    // From
    if (name === 'from') {
      const match = value.match(emailRegex);
      if (match) {
        result.from = match[0].toLowerCase();
        result.fromDomain = result.from.split('@')[1];
      }
      const nameMatch = value.match(/^"?([^"<]+?)"?\s*</);
      if (nameMatch) result.fromName = nameMatch[1].trim();
    }

    // To
    if (name === 'to') {
      const match = value.match(emailRegex);
      if (match) {
        result.to = match[0].toLowerCase();
        result.toDomain = result.to.split('@')[1];
      }
    }

    // Reply-To
    if (name === 'reply-to') {
      const match = value.match(emailRegex);
      if (match) {
        result.replyTo = match[0].toLowerCase();
        result.replyToDomain = result.replyTo.split('@')[1];
      }
    }

    // Return-Path
    if (name === 'return-path') {
      const match = value.match(emailRegex);
      if (match) {
        result.returnPath = match[0].toLowerCase();
        result.returnPathDomain = result.returnPath.split('@')[1];
      }
    }

    // Subject
    if (name === 'subject') result.subject = value;

    // Date
    if (name === 'date') result.date = value;

    // Message-ID
    if (name === 'message-id') result.messageId = value;

    // X-Mailer / User-Agent
    if (name === 'x-mailer' || name === 'user-agent') result.xMailer = value;

    // X-Original-From
    if (name === 'x-original-sender' || name === 'x-original-from') result.xOriginalFrom = value;

    // Content-Type
    if (name === 'content-type') result.contentType = value;

    // MIME-Version
    if (name === 'mime-version') result.mimeVersion = value;

    // List-Unsubscribe
    if (name === 'list-unsubscribe') result.listUnsubscribe = value;

    // Precedence
    if (name === 'precedence') result.precedence = value;

    // Received chain
    if (name === 'received') {
      const ips = value.match(ipv4Regex) || [];
      result.receivedChain.push({
        raw: value,
        ips: ips.filter(ip => !ip.startsWith('127.') && !ip.startsWith('10.') && !ip.startsWith('192.168.'))
      });
      ips.forEach(ip => {
        if (!ip.startsWith('127.') && !ip.startsWith('10.') && !ip.startsWith('192.168.') && !ip.startsWith('0.')) {
          result.rawIPs.push(ip);
        }
      });
    }

    // Authentication-Results
    if (name === 'authentication-results') {
      result.authenticationResults.push(value);
      const lower = value.toLowerCase();
      // SPF
      if (lower.includes('spf=')) {
        const m = lower.match(/spf=(pass|fail|softfail|neutral|temperror|permerror|none)/);
        if (m) result.spf = { result: m[1], detail: value };
      }
      // DKIM
      if (lower.includes('dkim=')) {
        const m = lower.match(/dkim=(pass|fail|neutral|none|temperror|permerror)/);
        if (m) result.dkim = { result: m[1], detail: value };
      }
      // DMARC
      if (lower.includes('dmarc=')) {
        const m = lower.match(/dmarc=(pass|fail|bestguesspass|none)/);
        if (m) result.dmarc = { result: m[1], detail: value };
      }
    }

    // ARC-Authentication-Results
    if (name === 'arc-authentication-results') {
      const lower = value.toLowerCase();
      const m = lower.match(/arc=(pass|fail|none)/);
      if (m) result.arc = { result: m[1] };
    }

    // Collect all X- headers
    if (name.startsWith('x-')) {
      result.xHeaders[name] = value;
    }
  }

  // Deduplicate IPs
  result.rawIPs = [...new Set(result.rawIPs)];

  return result;
}

// ──────────────────────────────────────────────
//  DNS Verification (live lookups)
// ──────────────────────────────────────────────
async function verifyDNS(domain) {
  const result = { spf: null, dmarc: null, mx: null, aRecords: null, errors: [] };
  if (!domain) return result;

  // For DMARC, also check the organizational (parent) domain
  // e.g. mail-eu.dreamapply.com → dreamapply.com
  const parts = domain.split('.');
  const orgDomain = parts.length > 2 ? parts.slice(-2).join('.') : domain;

  const tasks = [
    // SPF — check subdomain first, then fall back to org domain (like DMARC)
    (async () => {
      try {
        const records = await resolveTxt(domain);
        const flat = records.flat();
        const spfRec = flat.find(r => r.startsWith('v=spf1'));
        if (spfRec) {
          result.spf = { exists: true, record: spfRec, strict: spfRec.includes('-all'), softfail: spfRec.includes('~all'), source: domain };
          return;
        }
      } catch {}
      // Fall back to organizational (parent) domain
      if (orgDomain !== domain) {
        try {
          const records = await resolveTxt(orgDomain);
          const flat = records.flat();
          const spfRec = flat.find(r => r.startsWith('v=spf1'));
          if (spfRec) {
            result.spf = { exists: true, record: spfRec, strict: spfRec.includes('-all'), softfail: spfRec.includes('~all'), source: orgDomain };
            return;
          }
        } catch {}
      }
      result.spf = { exists: false };
    })(),

    // DMARC — check subdomain first, then fall back to org domain
    (async () => {
      try {
        const records = await resolveTxt(`_dmarc.${domain}`);
        const flat = records.flat();
        const dmarcRec = flat.find(r => r.startsWith('v=DMARC1'));
        if (dmarcRec) {
          const policy = dmarcRec.match(/p=(none|quarantine|reject)/);
          result.dmarc = { exists: true, record: dmarcRec, policy: policy?.[1] || 'unknown', source: domain };
          return;
        }
      } catch {}
      // Fall back to organizational domain
      if (orgDomain !== domain) {
        try {
          const records = await resolveTxt(`_dmarc.${orgDomain}`);
          const flat = records.flat();
          const dmarcRec = flat.find(r => r.startsWith('v=DMARC1'));
          if (dmarcRec) {
            const policy = dmarcRec.match(/p=(none|quarantine|reject)/);
            result.dmarc = { exists: true, record: dmarcRec, policy: policy?.[1] || 'unknown', source: orgDomain };
            return;
          }
        } catch {}
      }
      result.dmarc = { exists: false };
    })(),

    // MX — check subdomain first, then fall back to org domain
    (async () => {
      try {
        const records = await resolveMx(domain);
        if (records && records.length > 0) {
          result.mx = { exists: true, records: records.map(r => ({ priority: r.priority, exchange: r.exchange })) };
          return;
        }
      } catch {}
      // Fall back to organizational (parent) domain
      if (orgDomain !== domain) {
        try {
          const records = await resolveMx(orgDomain);
          if (records && records.length > 0) {
            result.mx = { exists: true, records: records.map(r => ({ priority: r.priority, exchange: r.exchange })) };
            return;
          }
        } catch {}
      }
      result.mx = { exists: false, records: [] };
    })(),

    // A records
    resolve4(domain).then(addrs => {
      result.aRecords = addrs;
    }).catch(() => { result.aRecords = []; }),
  ];

  await Promise.allSettled(tasks);
  return result;
}

// ──────────────────────────────────────────────
//  Reverse DNS lookups for IPs in Received chain
// ──────────────────────────────────────────────
async function resolveIPs(ips) {
  const results = [];
  for (const ip of ips.slice(0, 5)) { // cap at 5
    try {
      const hostnames = await reverse(ip);
      results.push({ ip, hostnames, suspicious: false });
    } catch {
      results.push({ ip, hostnames: [], suspicious: true, note: 'No reverse DNS — possible compromised host' });
    }
  }
  return results;
}

// ──────────────────────────────────────────────
//  Header Risk Scoring
// ──────────────────────────────────────────────
function scoreHeaders(headers, dnsResult, ipInfo) {
  let score = 0;
  const factors = [];
  const findings = [];
  let isVerifiedLegit = false;

  // ── 1. Sender Domain Trust ──
  if (headers.fromDomain) {
    const tld = '.' + headers.fromDomain.split('.').pop();
    const isTrusted = TRUSTED_SENDER_DOMAINS.has(headers.fromDomain) ||
                      [...TRUSTED_SENDER_DOMAINS].some(d => headers.fromDomain.endsWith('.' + d));
    const isInstitutional = INSTITUTIONAL_TLDS.some(p => p.test(headers.fromDomain));
    const isSuspiciousTLD = SUSPICIOUS_TLDS.has(tld);

    if (isTrusted) {
      score -= 0.25;
      factors.push('trusted_sender_domain');
      findings.push({ type: 'TRUSTED', detail: `Sender domain ${headers.fromDomain} is a known trusted domain`, severity: 'safe' });
      isVerifiedLegit = true;
    } else if (isInstitutional) {
      score -= 0.20;
      factors.push('institutional_domain');
      findings.push({ type: 'INSTITUTIONAL', detail: `Sender domain uses institutional TLD (${tld})`, severity: 'safe' });
      isVerifiedLegit = true;
    }

    if (isSuspiciousTLD && !isTrusted) {
      score += 0.20;
      factors.push('suspicious_tld');
      findings.push({ type: 'SUSPICIOUS_TLD', detail: `Sender uses suspicious TLD: ${tld}`, severity: 'high' });
    }

    // Brand impersonation check (includes leet-speak variants like paypa1, amaz0n, g00gle)
    const leetMap = { 'a': '[a4@]', 'e': '[e3]', 'i': '[i1!l|]', 'o': '[o0]', 'l': '[l1iI|]', 's': '[s5$]', 't': '[t7]', 'm': '(?:m|rn)', 'w': '(?:w|vv)', 'c': '[c¢]' };
    function brandToLeetRegex(brand) {
      const pattern = brand.split('').map(ch => leetMap[ch.toLowerCase()] || ch).join('');
      return new RegExp(pattern, 'i');
    }

    let brandImpersonationFound = false;
    for (const [brand, domains] of Object.entries(BRAND_DOMAINS)) {
      const leetRegex = brandToLeetRegex(brand);
      const exactMatch = headers.fromDomain.includes(brand);
      const leetMatch = leetRegex.test(headers.fromDomain);
      
      if ((exactMatch || leetMatch) && !domains.some(d => headers.fromDomain === d || headers.fromDomain.endsWith('.' + d))) {
        // Leet-speak variants (paypa1, amaz0n) get higher score — deliberate evasion
        const isLeetSpeak = !exactMatch && leetMatch;
        score += isLeetSpeak ? 0.45 : 0.35;
        factors.push(isLeetSpeak ? 'leetspeak_brand_impersonation' : 'brand_impersonation');
        findings.push({ 
          type: isLeetSpeak ? 'LEETSPEAK_BRAND_IMPERSONATION' : 'BRAND_IMPERSONATION', 
          detail: isLeetSpeak 
            ? `Domain uses leet-speak to impersonate "${brand}" (${headers.fromDomain}) — deliberate evasion tactic`
            : `Domain contains "${brand}" but is not an official ${brand} domain`, 
          severity: 'critical' 
        });
        brandImpersonationFound = true;
        break;
      }
    }

    // Look-alike domain (brand + suspicious TLD) — also leet-speak aware
    if (!brandImpersonationFound) {
      const brandNames = Object.keys(BRAND_DOMAINS);
      for (const brand of brandNames) {
        if (brand.length < 4) continue;
        const leetRegex = brandToLeetRegex(brand);
        if (leetRegex.test(headers.fromDomain) && isSuspiciousTLD) {
          score += 0.30;
          factors.push('lookalike_domain');
          findings.push({ type: 'LOOKALIKE_DOMAIN', detail: `Sender domain impersonates "${brand}" with a suspicious TLD (${tld})`, severity: 'critical' });
          break;
        }
      }
    } else if (isSuspiciousTLD) {
      // Brand impersonation PLUS suspicious TLD — extra penalty
      score += 0.20;
      factors.push('brand_plus_suspicious_tld');
      findings.push({ type: 'BRAND_SUSPICIOUS_TLD_COMBO', detail: `Brand impersonation combined with suspicious TLD (${tld}) — very high phishing confidence`, severity: 'critical' });
    }
  }

  // ── 2. Reply-To Mismatch ──
  if (headers.replyTo && headers.from && headers.replyToDomain !== headers.fromDomain) {
    if (!isVerifiedLegit) {
      score += 0.20;
      factors.push('reply_to_mismatch');
      findings.push({ type: 'REPLY_TO_MISMATCH', detail: `Reply-To (${headers.replyToDomain}) differs from From (${headers.fromDomain})`, severity: 'medium' });
    } else {
      findings.push({ type: 'REPLY_TO_MISMATCH_INFO', detail: `Reply-To differs but sender is trusted — may be a mailing list`, severity: 'info' });
    }
  }

  // ── 3. Return-Path Mismatch ──
  if (headers.returnPath && headers.from && headers.returnPathDomain !== headers.fromDomain) {
    if (!isVerifiedLegit) {
      score += 0.15;
      factors.push('return_path_mismatch');
      findings.push({ type: 'RETURN_PATH_MISMATCH', detail: `Return-Path (${headers.returnPathDomain}) differs from From (${headers.fromDomain})`, severity: 'medium' });
    }
  }

  // ── 4. SPF / DKIM / DMARC from headers ──
  if (headers.spf.result === 'fail') {
    score += 0.20;
    factors.push('spf_fail');
    findings.push({ type: 'SPF_FAIL', detail: 'SPF authentication failed — sender IP not authorized', severity: 'high' });
  } else if (headers.spf.result === 'softfail') {
    score += 0.10;
    factors.push('spf_softfail');
    findings.push({ type: 'SPF_SOFTFAIL', detail: 'SPF soft-fail — sender IP not explicitly authorized', severity: 'medium' });
  } else if (headers.spf.result === 'pass') {
    score -= 0.10;
    factors.push('spf_pass');
    findings.push({ type: 'SPF_PASS', detail: 'SPF passed — sender IP is authorized', severity: 'safe' });
  }

  if (headers.dkim.result === 'fail') {
    score += 0.20;
    factors.push('dkim_fail');
    findings.push({ type: 'DKIM_FAIL', detail: 'DKIM signature verification failed — email may be tampered', severity: 'high' });
  } else if (headers.dkim.result === 'pass') {
    score -= 0.10;
    factors.push('dkim_pass');
    findings.push({ type: 'DKIM_PASS', detail: 'DKIM signature valid — email integrity verified', severity: 'safe' });
  }

  if (headers.dmarc.result === 'fail') {
    score += 0.20;
    factors.push('dmarc_fail');
    findings.push({ type: 'DMARC_FAIL', detail: 'DMARC policy check failed — domain owner rejects this message', severity: 'high' });
  } else if (headers.dmarc.result === 'pass') {
    score -= 0.10;
    factors.push('dmarc_pass');
    findings.push({ type: 'DMARC_PASS', detail: 'DMARC passed — email aligns with domain policy', severity: 'safe' });
  }

  // Full authentication bonus
  if (headers.spf.result === 'pass' && headers.dkim.result === 'pass' && headers.dmarc.result === 'pass') {
    score -= 0.20;
    factors.push('fully_authenticated');
    findings.push({ type: 'FULLY_AUTHENTICATED', detail: 'All three authentication checks passed (SPF + DKIM + DMARC)', severity: 'safe' });
    // Note: Do not set isVerifiedLegit = true here. Authentication proves identity, but an attacker can authenticate their own phishing domain!
  }

  // ── Browser extraction detection ──
  // When ALL auth AND routing data is missing simultaneously, this is a clear
  // signal of a browser-based scan (content script can't see raw RFC 2822
  // headers). Instead of stacking 5 separate penalties (+0.50), apply a single
  // small penalty since "missing" ≠ "failed".
  const isBrowserExtraction = !headers.spf.result && !headers.dkim.result && !headers.dmarc.result
    && headers.receivedChain.length === 0 && !headers.messageId;

  if (isBrowserExtraction) {
    // ── 5b. DNS can still partially verify the domain ──
    if (dnsResult && headers.fromDomain) {
      const spfOk  = dnsResult.spf?.exists;
      const spfStrict = dnsResult.spf?.strict; // -all
      const dmarcOk = dnsResult.dmarc?.exists;
      const dmarcEnforced = dnsResult.dmarc?.policy === 'quarantine' || dnsResult.dmarc?.policy === 'reject';
      const mxOk   = dnsResult.mx?.exists;

      if (spfOk || dmarcOk) {
        // Domain has published DNS records — clearly legitimate infrastructure
        score -= 0.10;
        factors.push('dns_partial_verified');
        findings.push({ type: 'DNS_PARTIAL', detail: `Domain has ${[spfOk && 'SPF', dmarcOk && 'DMARC', mxOk && 'MX'].filter(Boolean).join(' + ')} — legitimate mail infrastructure`, severity: 'safe' });

        // When a domain has BOTH enforced DMARC (reject/quarantine) AND strict SPF (-all),
        // spoofing the From address is practically impossible — the receiving mail server
        // would reject or quarantine the forged email before it reaches the inbox.
        // In this case, it IS safe to trust the sender identity even from a browser scan.
        if (dmarcEnforced && spfStrict) {
          isVerifiedLegit = true;
          score -= 0.15;
          factors.push('dns_strongly_verified');
          findings.push({ type: 'DNS_STRONG_VERIFY', detail: `Domain ${headers.fromDomain} has enforced DMARC (${dnsResult.dmarc.policy}) + strict SPF (-all) — sender identity is cryptographically verified`, severity: 'safe' });
        }
      } else if (mxOk && !spfOk && !dmarcOk) {
        // Only MX found (DNS TXT lookups may have timed out) — don't penalize heavily
        score += 0.05;
        factors.push('browser_extraction_mx_only');
        findings.push({ type: 'BROWSER_SCAN_MX_ONLY', detail: 'Headers not available from browser extraction. Domain has MX records — DNS text lookups may have timed out', severity: 'info' });
      } else {
        // No DNS records at all — mildly suspicious
        score += 0.10;
        factors.push('browser_extraction_no_dns');
        findings.push({ type: 'BROWSER_SCAN_NO_DNS', detail: 'Headers not available from browser extraction and no DNS records found for sender domain', severity: 'low' });
      }
    } else {
      // No domain to check DNS for
      score += 0.10;
      factors.push('browser_extraction_unknown');
      findings.push({ type: 'BROWSER_SCAN', detail: 'Email headers not available from browser extraction — limited analysis', severity: 'info' });
    }

    findings.push({ type: 'BROWSER_EXTRACTION', detail: 'Scanned from browser — raw email headers are not accessible to the extension', severity: 'info' });

  } else {
    // ── Standard (non-browser) path: evaluate each signal individually ──

    // ── 5. DNS Verification (live) ──
    if (dnsResult && headers.fromDomain) {
      const spfOk  = dnsResult.spf?.exists;
      const dmarcOk = dnsResult.dmarc?.exists;
      const dmarcEnforced = dnsResult.dmarc?.policy === 'quarantine' || dnsResult.dmarc?.policy === 'reject';
      const mxOk   = dnsResult.mx?.exists;

      dnsVerified = !!(dmarcEnforced || (spfOk && dmarcOk && mxOk));

      if (dnsVerified) {
        score -= 0.20;
        factors.push('dns_verified_domain');
        const reason = dmarcEnforced
          ? `Domain ${headers.fromDomain} has enforced DMARC (${dnsResult.dmarc.policy}) — verified via live DNS`
          : `Domain ${headers.fromDomain} has SPF + DMARC + MX — verified via live DNS`;
        findings.push({ type: 'DNS_VERIFIED', detail: reason, severity: 'safe' });
        // Note: Do not set isVerifiedLegit = true here. Any domain owner (even an attacker) can publish valid DNS records!
      }

      if (!spfOk) {
        if (!dnsVerified) {
          score += 0.10;
          factors.push('no_spf_record');
          findings.push({ type: 'NO_SPF_RECORD', detail: `Sender domain has no SPF record published`, severity: 'medium' });
        } else {
          findings.push({ type: 'NO_SPF_RECORD_INFO', detail: 'No SPF record — common for noreply/send-only domains; DMARC compensates', severity: 'info' });
        }
      } else if (dnsResult.spf?.strict) {
        findings.push({ type: 'STRICT_SPF', detail: 'Domain uses strict SPF (-all) — good security', severity: 'safe' });
      }

      if (!dmarcOk) {
        score += 0.10;
        factors.push('no_dmarc_record');
        findings.push({ type: 'NO_DMARC_RECORD', detail: `Sender domain has no DMARC record published`, severity: 'medium' });
      } else if (dnsResult.dmarc?.policy === 'reject') {
        findings.push({ type: 'DMARC_REJECT_POLICY', detail: 'Domain has strict DMARC reject policy — strong protection', severity: 'safe' });
      } else if (dnsResult.dmarc?.policy === 'quarantine') {
        findings.push({ type: 'DMARC_QUARANTINE_POLICY', detail: 'Domain uses DMARC quarantine policy — good protection', severity: 'safe' });
      } else if (dnsResult.dmarc?.policy === 'none') {
        findings.push({ type: 'DMARC_NONE_POLICY', detail: 'DMARC policy is "none" — monitoring only, no enforcement', severity: 'info' });
      }

      if (!mxOk) {
        if (!dnsVerified) {
          score += 0.10;
          factors.push('no_mx_record');
          findings.push({ type: 'NO_MX', detail: 'Sender domain has no MX records — cannot receive replies', severity: 'medium' });
        } else {
          findings.push({ type: 'NO_MX_INFO', detail: 'No MX records — typical for noreply/send-only addresses', severity: 'info' });
        }
      }
    }

    // No authentication at all (from headers)
    if (!headers.spf.result && !headers.dkim.result && !headers.dmarc.result) {
      if (dnsVerified) {
        factors.push('no_authentication_dns_compensated');
        findings.push({ type: 'NO_AUTH_INFO', detail: 'SPF/DKIM/DMARC not visible in extracted headers (normal for browser-based scans) — domain verified via DNS', severity: 'info' });
      } else {
        score += 0.15;
        factors.push('no_authentication');
        findings.push({ type: 'NO_AUTH', detail: 'No SPF/DKIM/DMARC authentication results found in headers', severity: 'medium' });
      }
    }

    // ── 6. IP Reputation (Received chain) ──
    if (ipInfo && ipInfo.length > 0) {
      const suspiciousIPs = ipInfo.filter(i => i.suspicious);
      if (suspiciousIPs.length > 0) {
        score += 0.10 * Math.min(suspiciousIPs.length, 3);
        factors.push('suspicious_relay_ips');
        for (const ip of suspiciousIPs) {
          findings.push({ type: 'SUSPICIOUS_IP', detail: `IP ${ip.ip} in routing chain has no reverse DNS`, severity: 'medium' });
        }
      }
    }

    // ── 7. Unusual Received chain ──
    if (headers.receivedChain.length > 8) {
      score += 0.10;
      factors.push('excessive_hops');
      findings.push({ type: 'EXCESSIVE_HOPS', detail: `Email passed through ${headers.receivedChain.length} mail servers — unusual routing`, severity: 'medium' });
    }
    if (headers.receivedChain.length === 0 && !isVerifiedLegit) {
      score += 0.10;
      factors.push('no_received_headers');
      findings.push({ type: 'NO_RECEIVED', detail: 'No Received headers — email may be locally forged', severity: 'medium' });
    } else if (headers.receivedChain.length === 0 && isVerifiedLegit) {
      findings.push({ type: 'NO_RECEIVED_INFO', detail: 'Received headers not available from browser extraction — domain verified via DNS', severity: 'info' });
    }

    // ── 8. Missing Message-ID ──
    if (!headers.messageId && !isVerifiedLegit) {
      score += 0.05;
      factors.push('no_message_id');
      findings.push({ type: 'NO_MESSAGE_ID', detail: 'Missing Message-ID header — abnormal for legitimate email', severity: 'low' });
    } else if (!headers.messageId && isVerifiedLegit) {
      findings.push({ type: 'NO_MESSAGE_ID_INFO', detail: 'Message-ID not available from browser extraction — domain verified via DNS', severity: 'info' });
    }
  }

  return { score: Math.max(0, Math.min(1, score)), factors, findings, isVerifiedLegit };
}


// ════════════════════════════════════════════════════════════════
//  PHASE 2: BODY / STRUCTURE ANALYSIS
// ════════════════════════════════════════════════════════════════

function analyzeBody(subject, body, fromDomain) {
  let score = 0;
  const factors = [];
  const findings = [];

  const text = ((subject || '') + ' ' + (body || '')).toLowerCase();
  const bodyLower = (body || '').toLowerCase();
  const subjectLower = (subject || '').toLowerCase();

  // ── 1. Urgency / Pressure Language ──
  const urgencyPatterns = [
    /\b(urgent|immediately|right now|act now|asap|time.?sensitive)\b/i,
    /\b(your account (will be|has been|is) (suspended|locked|disabled|terminated|compromised))\b/i,
    /\b(verify your (identity|account|information|email))\b/i,
    /\b(within (24|48|72) hours)\b/i,
    /\b(failure to (comply|respond|verify))\b/i,
    /\b(unauthorized (access|activity|transaction))\b/i,
    /\b(security (alert|notice|warning|breach))\b/i,
    /\b(confirm your (payment|billing|details|identity))\b/i,
  ];
  let urgencyCount = 0;
  for (const p of urgencyPatterns) {
    if (p.test(text)) urgencyCount++;
  }
  if (urgencyCount >= 3) {
    score += 0.35;
    factors.push('high_urgency');
    findings.push({ type: 'HIGH_URGENCY', detail: `${urgencyCount} urgency/pressure phrases detected`, severity: 'high' });
  } else if (urgencyCount >= 1) {
    score += 0.15;
    factors.push('moderate_urgency');
    findings.push({ type: 'URGENCY', detail: `${urgencyCount} urgency/pressure phrase(s) found`, severity: 'medium' });
  }

  // ── 2. Financial / Credential Bait ──
  const financialPatterns = [
    /\b(credit card|debit card|bank account|wire transfer|social security)\b/i,
    /\b(routing number|account number|ssn|pin)\b/i,
    /\b(bitcoin|cryptocurrency|crypto wallet)\b/i,
    /\b(refund|payment|invoice|receipt|billing)\b/i,
    /\b(password|login credentials|username)\b/i,
    /\b(western union|money ?gram|gift card)\b/i,
    /\b(processing fee|transfer fee|handling fee|clearance fee)\b/i,
  ];
  let financialCount = 0;
  for (const p of financialPatterns) {
    if (p.test(text)) financialCount++;
  }
  if (financialCount >= 3) {
    score += 0.30;
    factors.push('financial_bait');
    findings.push({ type: 'FINANCIAL_BAIT', detail: `${financialCount} financial/credential-related keywords detected`, severity: 'high' });
  } else if (financialCount >= 1) {
    score += 0.10;
    factors.push('financial_reference');
    findings.push({ type: 'FINANCIAL_REF', detail: `${financialCount} financial keyword(s) found`, severity: 'low' });
  }

  // ── 2b. Advance-Fee Fraud / Money Scam Detection ──
  const scamPatterns = [
    /\b(you have been selected|you'?ve been (chosen|selected)|beneficiary)\b/i,
    /\b(inherit(ance|ed)|lottery|winner|winning|jackpot|prize)\b/i,
    /\b(million|billion)\s*(usd|dollars|euros|pounds|gbp)\b/i,
    /\b(claim your (funds|money|prize|winnings|inheritance))\b/i,
    /\b(send your (bank|account|personal) (details|information))\b/i,
    /\b(prince|royalt?y|diplomat|barrister|solicitor)\b/i,
    /\b(next of kin|unclaimed (funds|money|estate))\b/i,
    /\b(contact (me|us) (immediately|urgently|privately))\b/i,
    /\b(limited time offer|expires? (today|soon|tomorrow))\b/i,
    /\b(100% (safe|secure|guaranteed|risk.?free))\b/i,
  ];
  let scamCount = 0;
  for (const p of scamPatterns) {
    if (p.test(text)) scamCount++;
  }
  if (scamCount >= 3) {
    score += 0.50;
    factors.push('advance_fee_fraud');
    findings.push({ type: 'ADVANCE_FEE_FRAUD', detail: `${scamCount} advance-fee fraud/scam indicators detected (inheritance, lottery, or money scam)`, severity: 'critical' });
  } else if (scamCount >= 2) {
    score += 0.30;
    factors.push('money_scam_signals');
    findings.push({ type: 'MONEY_SCAM', detail: `${scamCount} money scam signal(s) detected`, severity: 'high' });
  } else if (scamCount >= 1) {
    score += 0.10;
    factors.push('scam_signal');
    findings.push({ type: 'SCAM_SIGNAL', detail: `Potential scam indicator found`, severity: 'medium' });
  }

  // ── 3. Suspicious URLs in Body ──
  const urls = body ? body.match(/https?:\/\/[^\s"'<>]+/gi) || [] : [];
  const suspiciousURLCount = urls.filter(u => {
    try {
      const h = new URL(u).hostname;
      const tld = '.' + h.split('.').pop();
      return SUSPICIOUS_TLDS.has(tld) || /\d{4,}/.test(h) || h.includes('-') && h.split('-').length > 3;
    } catch { return false; }
  }).length;

  if (suspiciousURLCount >= 2) {
    score += 0.30;
    factors.push('multiple_suspicious_urls');
    findings.push({ type: 'SUSPICIOUS_URLS', detail: `${suspiciousURLCount} URLs with suspicious domains found in body`, severity: 'high' });
  } else if (suspiciousURLCount === 1) {
    score += 0.15;
    factors.push('suspicious_url');
    findings.push({ type: 'SUSPICIOUS_URL', detail: 'A URL with a suspicious domain found in body', severity: 'medium' });
  }

  // ── 3b. Brand-mimicking URLs (e.g., paypa1-secure-login.xyz) ──
  const brandNames = Object.keys(BRAND_DOMAINS);
  for (const u of urls) {
    try {
      const h = new URL(u).hostname.toLowerCase();
      for (const brand of brandNames) {
        // Check if hostname contains a leet-speak or typo variant of the brand
        // e.g., "paypa1", "amaz0n", "g00gle", "microsooft"
        const leetBrand = brand.replace(/[aeiou]/gi, '.'); // allow any char in vowel positions
        const brandRegex = new RegExp(leetBrand, 'i');
        const officialDomains = BRAND_DOMAINS[brand];
        
        if ((h.includes(brand) || brandRegex.test(h)) && !officialDomains.some(d => h === d || h.endsWith('.' + d))) {
          score += 0.35;
          factors.push('brand_url_impersonation');
          findings.push({ type: 'BRAND_URL_IMPERSONATION', detail: `URL in email body impersonates "${brand}": ${h}`, severity: 'critical' });
          break;
        }
      }
    } catch {}
  }

  // Mismatched display text vs href (common phishing trick)
  // But skip common newsletter tracking/redirect patterns which are normal
  const mismatchedLinks = body ? (body.match(/<a[^>]+href=["']([^"']+)["'][^>]*>([^<]+)<\/a>/gi) || []) : [];
  let mismatchCount = 0;
  for (const link of mismatchedLinks) {
    const hrefMatch = link.match(/href=["']([^"']+)["']/i);
    const textMatch = link.match(/>([^<]+)</);
    if (hrefMatch && textMatch) {
      const href = hrefMatch[1];
      const displayText = textMatch[1].trim();
      // If display text looks like a URL but doesn't match href
      if (/https?:\/\//.test(displayText) || /\b[a-z]+\.(com|org|net)\b/i.test(displayText)) {
        try {
          const hrefHost = new URL(href).hostname;
          // Skip known newsletter tracking/redirect domains (not phishing)
          const isTracker = /\b(mailchimp|beehiiv|strava|mailgun|sendgrid|constantcontact|campaign-archive|list-manage|click\.|track\.|redirect\.|email\.|links\.|go\.|t\.)/i.test(hrefHost);
          if (!displayText.includes(hrefHost) && !isTracker) {
            mismatchCount++;
          }
        } catch {}
      }
    }
  }
  if (mismatchCount > 0) {
    score += 0.25;
    factors.push('link_text_mismatch');
    findings.push({ type: 'LINK_MISMATCH', detail: `${mismatchCount} link(s) show different URL than actual destination`, severity: 'high' });
  }

  // ── 4. Impersonal Greeting ──
  if (/^(dear (customer|user|valued|member|sir|madam|account holder)|hello,?\s*$)/im.test(text)) {
    score += 0.10;
    factors.push('impersonal_greeting');
    findings.push({ type: 'IMPERSONAL_GREETING', detail: 'Generic greeting used instead of recipient name', severity: 'low' });
  }

  // ── 5. Attachments (mentioned) ──
  if (/\b(see attached|open the attachment|download the file|attached (document|file|invoice|receipt))\b/i.test(text)) {
    score += 0.15;
    factors.push('attachment_bait');
    findings.push({ type: 'ATTACHMENT_BAIT', detail: 'Email urges opening an attachment — common malware vector', severity: 'medium' });
  }

  // ── 6. HTML-heavy with little text ──
  if (body && /<[a-z][\s\S]*>/i.test(body)) {
    const textOnly = body.replace(/<[^>]+>/g, '').trim();
    const htmlRatio = textOnly.length / body.length;
    if (htmlRatio < 0.15 && body.length > 500) {
      score += 0.10;
      factors.push('html_heavy');
      findings.push({ type: 'HTML_HEAVY', detail: 'Email is mostly HTML with very little visible text', severity: 'low' });
    }
  }

  // ── 7. Spelling / Grammar (quick heuristic) ──
  const grammarIssues = [
    /\b(kindly|do the needful|revert back|updation)\b/i,
    /\b(your|you) (has been|was been)\b/i,
    /\b(click below|click here to verify)\b/i,
  ];
  let grammarCount = grammarIssues.filter(p => p.test(text)).length;
  if (grammarCount >= 2) {
    score += 0.10;
    factors.push('grammar_issues');
    findings.push({ type: 'GRAMMAR', detail: 'Email contains common phishing grammar patterns', severity: 'low' });
  }

  // ── 8. Brand mention in body vs sender domain ──
  // Strip URLs AND common platform references (Google Play, App Store, etc.)
  // A Strava email saying "Download on Google Play" is NOT impersonating Google.
  const textNoUrls = text
    .replace(/https?:\/\/[^\s"'<>]+/gi, '')           // Remove full URLs
    .replace(/[a-z0-9.-]+\.(com|org|net|io|co)\b/gi, '') // Remove bare domains
    .replace(/\b(google\s+play|play\s+store|app\s+store|google\s+maps|google\s+chrome|google\s+analytics|google\s+fonts|google\s+ads|facebook\s+page|instagram\s+post|twitter\s+feed|linkedin\s+profile)\b/gi, ''); // Remove platform names
  if (fromDomain) {
    for (const [brand, domains] of Object.entries(BRAND_DOMAINS)) {
      const brandRegex = new RegExp(`\\b${brand}\\b`, 'gi');
      const matches = textNoUrls.match(brandRegex);
      // Require 2+ standalone brand mentions to trigger (single mention is likely incidental)
      if (matches && matches.length >= 2 && !domains.some(d => fromDomain === d || fromDomain.endsWith('.' + d))) {
        score += 0.20;
        factors.push('brand_body_mismatch');
        findings.push({ type: 'BRAND_BODY_MISMATCH', detail: `Email mentions "${brand}" ${matches.length} times but sent from unrelated domain ${fromDomain}`, severity: 'high' });
        break;
      }
    }
  }

  return { score: Math.max(0, Math.min(1, score)), factors, findings };
}


// ════════════════════════════════════════════════════════════════
//  PHASE 3: COMBINED VERDICT
// ════════════════════════════════════════════════════════════════

function computeVerdict(headerScore, bodyScore, isVerifiedLegit) {
  // Header analysis is weighted 60%, body 40%
  // If header shows fully authenticated + trusted domain, dampen body signals
  const headerWeight = 0.60;
  const bodyWeight = 0.40;

  let combined;
  if (isVerifiedLegit) {
    // Trusted & authenticated — body signals are likely false positives
    // Google/Microsoft security emails naturally contain urgency language,
    // tracking links, etc. Heavy dampening prevents false positives.
    combined = headerScore.score * headerWeight + bodyScore.score * bodyWeight * 0.15;
  } else {
    combined = headerScore.score * headerWeight + bodyScore.score * bodyWeight;
  }

  combined = Math.max(0, Math.min(1, combined));
  let percentage = Math.round(combined * 100);

  // ── Critical Finding Override ──
  // If any finding was marked 'critical' (e.g. brand impersonation, leet-speak),
  // this is a definitive phishing attack. Do not let the score get watered down.
  // BUT: skip this override if the sender is verified legitimate — critical
  // findings from body analysis are false positives for trusted senders
  // (e.g. Google security emails naturally mention "verify your account").
  const hasCritical = [...headerScore.findings, ...bodyScore.findings].some(f => f.severity === 'critical');
  if (hasCritical && !isVerifiedLegit && percentage < 80) {
    percentage = Math.max(80, percentage);
  }

  // ── Verified Legit Cap ──
  // A verified legitimate sender (trusted domain + DNS verified) should never
  // be marked malicious. Cap the score below the CAUTION threshold.
  if (isVerifiedLegit && percentage >= 30) {
    percentage = Math.min(percentage, 29);
  }

  let verdict, severity;
  if (percentage >= 70) {
    verdict = 'MALICIOUS';
    severity = 'critical';
  } else if (percentage >= 45) {
    verdict = 'SUSPICIOUS';
    severity = 'high';
  } else if (percentage >= 30) {
    verdict = 'CAUTION';
    severity = 'medium';
  } else {
    verdict = 'SAFE';
    severity = 'safe';
  }

  return { verdict, severity, score: percentage, combined, isVerifiedLegit };
}


// ════════════════════════════════════════════════════════════════
//  LABELED/PASTED EMAIL FORMAT PARSER
//  Detects when users paste email content with human-readable labels
//  like "Sender Email:", "Subject:", "Email Body:" instead of raw
//  RFC 2822 headers. Returns null if not a labeled format.
// ════════════════════════════════════════════════════════════════
function parseLabeledEmail(text) {
  if (!text || typeof text !== 'string') return null;

  const lines = text.split(/\r?\n/);

  // Quick heuristic: count how many labeled fields we recognize
  const labelPatterns = [
    /^sender\s*(?:email|name)/i,
    /^(?:from\s*(?:email|name))/i,
    /^receiver\s*(?:email|name)/i,
    /^(?:to\s*(?:email|name))/i,
    /^email\s*body/i,
    /^subject\s*:/i,
    /^label\s*:/i,
  ];

  let labelCount = 0;
  for (const line of lines) {
    const trimmed = line.trim();
    if (labelPatterns.some(p => p.test(trimmed))) labelCount++;
  }

  // Need at least 2 recognized labels to treat as labeled format
  if (labelCount < 2) return null;

  const result = { from: null, fromName: null, to: null, toName: null, subject: null, body: null };
  const emailRegex = /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/;
  let bodyStartIdx = -1;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;

    const colonIdx = line.indexOf(':');
    if (colonIdx === -1) continue;

    const label = line.substring(0, colonIdx).trim().toLowerCase();
    const value = line.substring(colonIdx + 1).trim();

    if (label === 'sender email' || label === 'from email') {
      const match = value.match(emailRegex);
      result.from = match ? match[0] : value;
    } else if (label === 'sender name' || label === 'from name' || label === 'sender') {
      // "Sender:" alone could be a name; if it has an email, treat as from
      const match = value.match(emailRegex);
      if (match) {
        result.from = match[0];
      } else {
        result.fromName = value;
      }
    } else if (label === 'receiver email' || label === 'to email') {
      const match = value.match(emailRegex);
      result.to = match ? match[0] : value;
    } else if (label === 'receiver name' || label === 'to name' || label === 'receiver') {
      const match = value.match(emailRegex);
      if (match) {
        result.to = match[0];
      } else {
        result.toName = value;
      }
    } else if (label === 'subject') {
      result.subject = value;
    } else if (label === 'email body' || label === 'body') {
      // Everything after this line is the email body
      bodyStartIdx = i + 1;
      // If value is on the same line as "Email Body:", include it
      if (value) {
        bodyStartIdx = i;
        // Re-extract: the body is the value + remaining lines
        result.body = value + '\n' + lines.slice(i + 1).join('\n');
      } else {
        result.body = lines.slice(bodyStartIdx).join('\n');
      }
      result.body = result.body.trim();
      break; // Stop — everything after is body
    }
  }

  // If no explicit "Email Body:" label was found, try to use everything
  // after the last recognized label as the body
  if (result.body === null) {
    // Find the last recognized label line
    let lastLabelIdx = -1;
    for (let i = 0; i < lines.length; i++) {
      const trimmed = lines[i].trim();
      if (labelPatterns.some(p => p.test(trimmed))) lastLabelIdx = i;
    }
    if (lastLabelIdx !== -1 && lastLabelIdx < lines.length - 1) {
      result.body = lines.slice(lastLabelIdx + 1).join('\n').trim();
    }
  }

  return result;
}


// ════════════════════════════════════════════════════════════════
//  MAIN ROUTE: POST /api/v1/emails/scan
// ════════════════════════════════════════════════════════════════

router.post('/scan', async (req, res) => {
  const startTime = Date.now();
  try {
    const { headers: rawHeaders, subject, body, rawEmail } = req.body;

    if (!rawHeaders && !rawEmail && !subject && !body) {
      return res.status(400).json({
        success: false,
        message: 'Email data required. Send { headers, subject, body } or { rawEmail }.'
      });
    }

    // If rawEmail provided, split into headers and body
    let headerText = rawHeaders || '';
    let emailSubject = subject || '';
    let emailBody = body || '';

    if (rawEmail && !rawHeaders) {
      // ── Detect "labeled/pasted" format ──
      // Users often paste emails in a human-readable format like:
      //   Sender Email: foo@bar.com
      //   Subject: Hello
      //   Email Body:
      //   ...actual body...
      // This is NOT RFC 2822 — the old code split on first \n\n which broke
      // everything (e.g. "Label: PHISHING\n\n" became the only "header").
      const labeledFields = parseLabeledEmail(rawEmail);
      if (labeledFields) {
        console.log('[Email Scan] Detected labeled/pasted email format — extracting fields');
        // Build synthetic RFC headers from the labeled fields
        const syntheticHeaders = [];
        if (labeledFields.from) {
          syntheticHeaders.push(
            labeledFields.fromName
              ? `From: "${labeledFields.fromName}" <${labeledFields.from}>`
              : `From: ${labeledFields.from}`
          );
        }
        if (labeledFields.to) {
          syntheticHeaders.push(
            labeledFields.toName
              ? `To: "${labeledFields.toName}" <${labeledFields.to}>`
              : `To: ${labeledFields.to}`
          );
        }
        if (labeledFields.subject) {
          syntheticHeaders.push(`Subject: ${labeledFields.subject}`);
          emailSubject = labeledFields.subject;
        }
        headerText = syntheticHeaders.join('\n');
        emailBody = labeledFields.body || '';
        console.log(`[Email Scan] Extracted — from: ${labeledFields.from || '(none)'}, subject: ${labeledFields.subject || '(none)'}, bodyLen: ${emailBody.length}`);
      } else {
        // Standard RFC 2822 format: split on first blank line
        const divider = rawEmail.indexOf('\r\n\r\n');
        const divider2 = rawEmail.indexOf('\n\n');
        const splitIdx = divider !== -1 ? divider : divider2;
        if (splitIdx !== -1) {
          headerText = rawEmail.substring(0, splitIdx);
          emailBody = emailBody || rawEmail.substring(splitIdx + (divider !== -1 ? 4 : 2));
        } else {
          headerText = rawEmail;
        }
      }
    }

    console.log(`[Email Scan] Starting analysis...`);

    // ── PHASE 1: Parse & Score Headers ──
    const parsedHeaders = parseHeaders(headerText);
    if (!emailSubject && parsedHeaders.subject) emailSubject = parsedHeaders.subject;

    // Live DNS verification + IP resolution (parallel)
    const [dnsResult, ipInfo] = await Promise.all([
      parsedHeaders.fromDomain ? verifyDNS(parsedHeaders.fromDomain) : null,
      parsedHeaders.rawIPs.length > 0 ? resolveIPs(parsedHeaders.rawIPs) : []
    ]);

    const headerAnalysis = scoreHeaders(parsedHeaders, dnsResult, ipInfo);

    console.log(`[Email Scan] Phase 1 (Headers): score=${headerAnalysis.score.toFixed(3)}, factors=[${headerAnalysis.factors.join(', ')}]`);

    // ── PHASE 2: Body & Structure Analysis ──
    const bodyAnalysis = analyzeBody(emailSubject, emailBody, parsedHeaders.fromDomain);

    console.log(`[Email Scan] Phase 2 (Body): score=${bodyAnalysis.score.toFixed(3)}, factors=[${bodyAnalysis.factors.join(', ')}]`);

    // ── PHASE 2.5: Quishing (QR Code) Analysis ──
    console.log(`[Email Scan] Phase 2.5 (Quishing): Scanning for QR codes...`);
    const qrUrls = await extractAndDecodeQRCodes(emailBody);
    
    let qrMalicious = false;
    let qrUrlStr = '';

    if (qrUrls && qrUrls.length > 0) {
      console.log(`[Email Scan] Found ${qrUrls.length} QR code(s) with URL(s)`);
      for (const qUrl of qrUrls) {
        qrUrlStr = qUrl;
        // Check if the URL is malicious using the multi-source threat intel engine
        try {
          const apiKeys = {
            googleSafeBrowsing: process.env.GOOGLE_SAFE_BROWSING_API_KEY || process.env.GSB_API_KEY || null,
            virusTotal: process.env.VIRUSTOTAL_API_KEY || null,
            abuseIPDB: process.env.ABUSEIPDB_API_KEY || null,
            shodan: process.env.SHODAN_API_KEY || null,
            urlhaus: process.env.URLHAUS_API_KEY || null,
            huggingFace: process.env.HUGGINGFACE_API_TOKEN || null,
          };
          const urlScanResult = await scanUrlMultiSource(qUrl, apiKeys);
          if (urlScanResult && (urlScanResult.status === 'MALICIOUS' || urlScanResult.status === 'SUSPICIOUS')) {
            qrMalicious = true;
            bodyAnalysis.findings.push({
              type: 'QUISHING_DETECTED',
              detail: `Malicious URL hidden inside a QR Code: ${qUrl} (Score: ${urlScanResult.score}/100)`,
              severity: 'critical'
            });
            bodyAnalysis.factors.push('quishing_detected');
            bodyAnalysis.score = 1.0; // Max out score
            break;
          } else {
             bodyAnalysis.findings.push({
              type: 'QR_CODE_FOUND',
              detail: `QR Code found containing safe URL: ${qUrl}`,
              severity: 'info'
            });
          }
        } catch (e) {
          console.error('[Email Scan] Error scanning QR URL:', e.message);
        }
      }
    }

    // ── PHASE 3: Combined Verdict ──
    let verdict = computeVerdict(headerAnalysis, bodyAnalysis, headerAnalysis.isVerifiedLegit);

    // If Quishing was detected, override verdict
    if (qrMalicious) {
      verdict.verdict = 'MALICIOUS';
      verdict.severity = 'critical';
      verdict.score = 100;
    }

    const elapsed = Date.now() - startTime;

    console.log(`[Email Scan] Verdict: ${verdict.verdict} (score: ${verdict.score}) in ${elapsed}ms`);

    // ── Save to DB so email scans appear in dashboard Recent Scans ──
    try {
      let userId = null;

      // Try extracting user from auth token
      const token = req.headers.authorization?.split(' ')[1];
      if (token) {
        try {
          const decoded = verifyAccessToken(token);
          if (decoded && decoded.id) userId = decoded.id;
        } catch {}
      }

      // Fallback: most recently logged-in user
      if (!userId) {
        const User = require('../models/User');
        const recentUser = await User.findOne({ lastLoginDate: { $ne: null } })
          .sort({ lastLoginDate: -1 })
          .select('_id')
          .lean();
        if (recentUser) userId = recentUser._id.toString();
      }

      if (userId) {
        const senderAddr = parsedHeaders.from || 'unknown';
        const senderDomain = parsedHeaders.fromDomain || '';
        const dbStatus = verdict.verdict === 'SAFE' ? 'safe' : 'unsafe';
        const allFindings = [
          ...(headerAnalysis.findings || []),
          ...(bodyAnalysis.findings || [])
        ];
        const threatFindings = allFindings.filter(f => f.severity === 'high' || f.severity === 'critical');
        const reasonStrings = threatFindings.map(f => f.detail || f.type);
        const indicatorStrings = threatFindings.map(f => f.type || 'THREAT');
        const issueStrings = threatFindings.length > 0
          ? threatFindings.map(f => `${(f.type || 'THREAT').replace(/_/g, ' ')}: ${f.detail || ''}`)
          : ['No security threats detected'];
        const confidence = dbStatus === 'safe'
          ? Math.max(0, 100 - verdict.score)
          : Math.min(100, Math.max(verdict.score, 50));

        await URLCheckHistory.create({
          userId,
          url: `email://${senderAddr}`,
          domain: senderDomain,
          status: dbStatus,
          reasons: reasonStrings,
          userAction: 'visited',
          wasWarned: verdict.verdict !== 'SAFE',
          threatScore: verdict.score,
          confidence,
          scanType: 'email',
          threatLevel: (() => {
            const v = verdict.verdict;
            if (v === 'SAFE') return 'safe';
            if (v === 'MALICIOUS') return 'high';
            if (v === 'SUSPICIOUS') return 'medium';
            if (v === 'CAUTION') return 'medium';
            return verdict.score >= 70 ? 'high' : (verdict.score >= 40 ? 'medium' : 'low');
          })(),
          threatType: threatFindings.length > 0 ? (threatFindings[0].type || 'unknown') : null,
          isSafe: verdict.verdict === 'SAFE',
          summary: `Email from ${senderAddr}: ${verdict.verdict} (score ${verdict.score})`,
          indicators: indicatorStrings,
          issues: issueStrings,
          senderEmail: senderAddr,
        });
        console.log(`[Email Scan] Saved to DB for user ${userId}: ${senderAddr} -> ${dbStatus}`);
      }
    } catch (saveErr) {
      console.error('[Email Scan] DB save error (non-fatal):', saveErr.message);
    }

    res.json({
      success: true,
      verdict: verdict.verdict,
      severity: verdict.severity,
      score: verdict.score,

      headerAnalysis: {
        score: Math.round(headerAnalysis.score * 100),
        factors: headerAnalysis.factors,
        findings: headerAnalysis.findings,
        isVerifiedLegit: headerAnalysis.isVerifiedLegit,
        sender: {
          from: parsedHeaders.from,
          fromName: parsedHeaders.fromName,
          fromDomain: parsedHeaders.fromDomain,
          replyTo: parsedHeaders.replyTo,
          returnPath: parsedHeaders.returnPath,
        },
        authentication: {
          spf: parsedHeaders.spf,
          dkim: parsedHeaders.dkim,
          dmarc: parsedHeaders.dmarc,
          arc: parsedHeaders.arc,
          fullyAuthenticated: headerAnalysis.factors.includes('fully_authenticated'),
        },
        dns: dnsResult ? {
          spf: dnsResult.spf,
          dmarc: dnsResult.dmarc,
          mx: dnsResult.mx,
        } : null,
        routing: {
          hops: parsedHeaders.receivedChain.length,
          ips: parsedHeaders.rawIPs,
          ipDetails: ipInfo,
        },
        metadata: {
          date: parsedHeaders.date,
          messageId: parsedHeaders.messageId,
          xMailer: parsedHeaders.xMailer,
          listUnsubscribe: !!parsedHeaders.listUnsubscribe,
          contentType: parsedHeaders.contentType,
        },
      },

      bodyAnalysis: {
        score: Math.round(bodyAnalysis.score * 100),
        factors: bodyAnalysis.factors,
        findings: bodyAnalysis.findings,
        subject: emailSubject || null,
      },

      meta: {
        scanTime: elapsed,
        timestamp: new Date().toISOString(),
      }
    });

  } catch (error) {
    console.error('[Email Scan] Error:', error);
    res.status(500).json({
      success: false,
      message: 'Email scan failed',
      error: error.message
    });
  }
});

module.exports = router;
