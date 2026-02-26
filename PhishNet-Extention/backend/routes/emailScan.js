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
const { promisify } = require('util');
const router = express.Router();
const { verifyAccessToken } = require('../utils/jwt');
const URLCheckHistory = require('../models/URLCheckHistory');

const resolveTxt = promisify(dns.resolveTxt);
const resolveMx = promisify(dns.resolveMx);
const resolve4 = promisify(dns.resolve4);
const reverse = promisify(dns.reverse);

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
    const name = line.substring(0, colonIdx).trim().toLowerCase();
    const value = line.substring(colonIdx + 1).trim();

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
    // SPF
    resolveTxt(domain).then(records => {
      const flat = records.flat();
      const spfRec = flat.find(r => r.startsWith('v=spf1'));
      result.spf = spfRec ? {
        exists: true, record: spfRec,
        strict: spfRec.includes('-all'),
        softfail: spfRec.includes('~all'),
      } : { exists: false };
    }).catch(e => { result.spf = { exists: false, error: e.code }; }),

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

    // MX
    resolveMx(domain).then(records => {
      result.mx = { exists: records.length > 0, records: records.map(r => ({ priority: r.priority, exchange: r.exchange })) };
    }).catch(e => { result.mx = { exists: false, error: e.code }; }),

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

    // Brand impersonation check
    for (const [brand, domains] of Object.entries(BRAND_DOMAINS)) {
      if (headers.fromDomain.includes(brand) && !domains.some(d => headers.fromDomain === d || headers.fromDomain.endsWith('.' + d))) {
        score += 0.35;
        factors.push('brand_impersonation');
        findings.push({ type: 'BRAND_IMPERSONATION', detail: `Domain contains "${brand}" but is not an official ${brand} domain`, severity: 'critical' });
        break;
      }
    }

    // Look-alike domain (brand + suspicious TLD)
    const brandPattern = /(paypal|amazon|google|microsoft|apple|netflix|chase|facebook|instagram|linkedin|twitter|dropbox|bankofamerica)/i;
    if (brandPattern.test(headers.fromDomain) && isSuspiciousTLD) {
      score += 0.30;
      factors.push('lookalike_domain');
      findings.push({ type: 'LOOKALIKE_DOMAIN', detail: `Sender domain combines a brand name with a suspicious TLD`, severity: 'critical' });
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
    isVerifiedLegit = true;
  }

  // ── 5. DNS Verification (live) ──
  // DNS verification can compensate when header auth is missing (content script
  // can't extract raw RFC 2822 headers — missing ≠ failed)
  let dnsVerified = false;
  if (dnsResult && headers.fromDomain) {
    const spfOk  = dnsResult.spf?.exists;
    const dmarcOk = dnsResult.dmarc?.exists;
    const dmarcEnforced = dnsResult.dmarc?.policy === 'quarantine' || dnsResult.dmarc?.policy === 'reject';
    const mxOk   = dnsResult.mx?.exists;

    // Strong domain verification:
    // Tier 1: DMARC enforced (reject/quarantine) — strongest signal, sufficient alone
    //         (many noreply@ domains intentionally omit SPF/MX)
    // Tier 2: SPF + DMARC published (any) + MX — classic full stack
    dnsVerified = !!(dmarcEnforced || (spfOk && dmarcOk && mxOk));

    if (dnsVerified) {
      score -= 0.20;
      factors.push('dns_verified_domain');
      const reason = dmarcEnforced
        ? `Domain ${headers.fromDomain} has enforced DMARC (${dnsResult.dmarc.policy}) — verified via live DNS`
        : `Domain ${headers.fromDomain} has SPF + DMARC + MX — verified via live DNS`;
      findings.push({ type: 'DNS_VERIFIED', detail: reason, severity: 'safe' });
      isVerifiedLegit = true;
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
  // If DNS verification confirmed the domain, this is just a content-script
  // extraction limitation — report as info, don't penalize.
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
  // Missing Received/Message-ID is expected when scanning from Gmail/Outlook DOM
  // (content script can't see raw headers). Only penalize if DNS also looks bad.
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
    score += 0.25;
    factors.push('multiple_suspicious_urls');
    findings.push({ type: 'SUSPICIOUS_URLS', detail: `${suspiciousURLCount} URLs with suspicious domains found in body`, severity: 'high' });
  } else if (suspiciousURLCount === 1) {
    score += 0.10;
    factors.push('suspicious_url');
    findings.push({ type: 'SUSPICIOUS_URL', detail: 'A URL with a suspicious domain found in body', severity: 'medium' });
  }

  // Mismatched display text vs href (common phishing trick)
  const mismatchedLinks = body ? (body.match(/<a[^>]+href=["']([^"']+)["'][^>]*>([^<]+)<\/a>/gi) || []) : [];
  let mismatchCount = 0;
  for (const link of mismatchedLinks) {
    const hrefMatch = link.match(/href=["']([^"']+)["']/i);
    const textMatch = link.match(/>([^<]+)</);
    if (hrefMatch && textMatch) {
      const href = hrefMatch[1];
      const displayText = textMatch[1];
      // If display text looks like a URL but doesn't match href
      if (/https?:\/\//.test(displayText) || /\b[a-z]+\.(com|org|net)\b/i.test(displayText)) {
        try {
          const hrefHost = new URL(href).hostname;
          if (!displayText.includes(hrefHost)) {
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
  if (fromDomain) {
    for (const [brand, domains] of Object.entries(BRAND_DOMAINS)) {
      if (text.includes(brand) && !domains.some(d => fromDomain === d || fromDomain.endsWith('.' + d))) {
        score += 0.20;
        factors.push('brand_body_mismatch');
        findings.push({ type: 'BRAND_BODY_MISMATCH', detail: `Email mentions "${brand}" but sent from unrelated domain ${fromDomain}`, severity: 'high' });
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
    combined = headerScore.score * headerWeight + bodyScore.score * bodyWeight * 0.3;
  } else {
    combined = headerScore.score * headerWeight + bodyScore.score * bodyWeight;
  }

  combined = Math.max(0, Math.min(1, combined));
  const percentage = Math.round(combined * 100);

  let verdict, severity;
  if (percentage >= 70) {
    verdict = 'MALICIOUS';
    severity = 'critical';
  } else if (percentage >= 45) {
    verdict = 'SUSPICIOUS';
    severity = 'high';
  } else if (percentage >= 25) {
    verdict = 'CAUTION';
    severity = 'medium';
  } else {
    verdict = 'SAFE';
    severity = 'safe';
  }

  return { verdict, severity, score: percentage, combined, isVerifiedLegit };
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

    // ── PHASE 3: Combined Verdict ──
    const verdict = computeVerdict(headerAnalysis, bodyAnalysis, headerAnalysis.isVerifiedLegit);
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
          threatLevel: verdict.verdict === 'SAFE' ? 'safe' : (verdict.score >= 70 ? 'high' : (verdict.score >= 40 ? 'medium' : 'low')),
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
