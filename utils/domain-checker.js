/**
 * Domain Verification Utility
 * Performs real DNS lookups for SPF, DKIM, and domain verification
 */

import dns from 'dns';
import { promisify } from 'util';

const resolveTxt = promisify(dns.resolveTxt);
const resolveMx = promisify(dns.resolveMx);
const resolve = promisify(dns.resolve);

class DomainChecker {
  constructor() {
    // Known legitimate domains for popular brands
    this.legitimateDomains = {
      netflix: ['netflix.com', 'netflix.net', 'nflximg.com'],
      amazon: ['amazon.com', 'amazon.co.uk', 'amazonses.com', 'amazon.in'],
      paypal: ['paypal.com', 'paypal.co.uk', 'paypal.me'],
      microsoft: ['microsoft.com', 'microsoftonline.com', 'outlook.com', 'office.com', 'live.com'],
      apple: ['apple.com', 'icloud.com', 'me.com'],
      google: ['google.com', 'gmail.com', 'googlemail.com', 'youtube.com'],
      chase: ['chase.com', 'jpmchase.com', 'jpmorganfunds.com'],
      bankofamerica: ['bankofamerica.com', 'bofa.com', 'mbna.com'],
      wellsfargo: ['wellsfargo.com', 'wf.com'],
      citibank: ['citi.com', 'citibank.com', 'citicards.com'],
      linkedin: ['linkedin.com', 'limail.com'],
      facebook: ['facebook.com', 'fb.com', 'meta.com', 'instagram.com'],
      twitter: ['twitter.com', 'x.com'],
      dropbox: ['dropbox.com', 'dropboxmail.com'],
      spotify: ['spotify.com'],
      uber: ['uber.com'],
      airbnb: ['airbnb.com']
    };

    // Suspicious TLDs often used in phishing
    this.suspiciousTLDs = ['.xyz', '.top', '.click', '.link', '.info', '.online', '.site', '.club', '.work', '.live', '.gq', '.ml', '.cf', '.tk', '.ga'];
  }

  /**
   * Check if a domain has valid SPF record
   */
  async checkSPF(domain) {
    try {
      const records = await resolveTxt(domain);
      const spfRecord = records.flat().find(r => r.startsWith('v=spf1'));
      
      if (spfRecord) {
        return {
          exists: true,
          record: spfRecord,
          hasStrict: spfRecord.includes('-all'),
          hasSoftFail: spfRecord.includes('~all')
        };
      }
      return { exists: false, record: null };
    } catch (error) {
      return { exists: false, error: error.code };
    }
  }

  /**
   * Check if domain has DMARC record
   */
  async checkDMARC(domain) {
    try {
      const dmarcDomain = `_dmarc.${domain}`;
      const records = await resolveTxt(dmarcDomain);
      const dmarcRecord = records.flat().find(r => r.startsWith('v=DMARC1'));
      
      if (dmarcRecord) {
        const policy = dmarcRecord.match(/p=(none|quarantine|reject)/);
        return {
          exists: true,
          record: dmarcRecord,
          policy: policy ? policy[1] : 'unknown'
        };
      }
      return { exists: false, record: null };
    } catch (error) {
      return { exists: false, error: error.code };
    }
  }

  /**
   * Check if domain has MX records (can receive email)
   */
  async checkMX(domain) {
    try {
      const records = await resolveMx(domain);
      return {
        exists: records.length > 0,
        records: records.map(r => ({ priority: r.priority, exchange: r.exchange }))
      };
    } catch (error) {
      return { exists: false, error: error.code };
    }
  }

  /**
   * Check domain age indicator (has DNS records)
   */
  async checkDomainExists(domain) {
    try {
      await resolve(domain);
      return { exists: true };
    } catch (error) {
      return { exists: false, error: error.code };
    }
  }

  /**
   * Verify if sender domain matches claimed brand
   */
  verifyBrandDomain(senderDomain, claimedBrand) {
    if (!senderDomain || !claimedBrand) return { verified: null, reason: 'Missing data' };

    const brandLower = claimedBrand.toLowerCase();
    const domainLower = senderDomain.toLowerCase();

    for (const [brand, domains] of Object.entries(this.legitimateDomains)) {
      if (brandLower.includes(brand)) {
        const isLegitimate = domains.some(d => domainLower === d || domainLower.endsWith(`.${d}`));
        return {
          verified: isLegitimate,
          expectedDomains: domains,
          actualDomain: senderDomain,
          brand: brand,
          reason: isLegitimate 
            ? `Domain ${senderDomain} is a verified ${brand} domain`
            : `Domain ${senderDomain} does NOT match official ${brand} domains`
        };
      }
    }

    return { verified: null, reason: 'Brand not in verification database' };
  }

  /**
   * Check for suspicious domain patterns
   */
  checkSuspiciousPatterns(domain) {
    const issues = [];
    const domainLower = domain.toLowerCase();
    
    // Extract base domain (e.g., www.paypal.com -> paypal.com)
    const parts = domainLower.split('.');
    const baseDomain = parts.length >= 2 ? parts.slice(-2).join('.') : domainLower;

    // Check suspicious TLDs
    for (const tld of this.suspiciousTLDs) {
      if (domainLower.endsWith(tld)) {
        issues.push(`Suspicious TLD: ${tld}`);
      }
    }

    // Check for brand names in suspicious domains
    for (const brand of Object.keys(this.legitimateDomains)) {
      // Check if domain contains brand name
      if (domainLower.includes(brand)) {
        // Check if base domain or full domain is in legitimate list
        const isLegitimate = this.legitimateDomains[brand].some(legit => 
          baseDomain === legit || domainLower === legit || domainLower.endsWith(`.${legit}`)
        );
        if (!isLegitimate) {
          issues.push(`Contains "${brand}" but is not official domain`);
        }
      }
    }

    // Check for lookalike characters (homograph attack)
    if (/[0-9]/.test(domain.replace(/\.[a-z]+$/, ''))) {
      // Numbers in domain name (excluding TLD) - common in phishing
      if (/paypa[l1]|amaz[o0]n|g[o0]{2}gle|micr[o0]s[o0]ft|faceb[o0]{2}k/i.test(domain)) {
        issues.push('Possible lookalike/typosquatting domain');
      }
    }

    // Check for excessive subdomains
    const subdomainCount = domain.split('.').length - 2;
    if (subdomainCount > 2) {
      issues.push(`Excessive subdomains (${subdomainCount})`);
    }

    // Check for suspicious keywords (only if not a legitimate domain)
    const hasLegitBrand = Object.values(this.legitimateDomains).flat().some(legit => 
      baseDomain === legit || domainLower.endsWith(`.${legit}`)
    );
    if (!hasLegitBrand && /secure|verify|update|confirm|login|account|alert|billing|support/i.test(domain)) {
      issues.push('Contains suspicious security-related keywords');
    }

    return {
      suspicious: issues.length > 0,
      issues
    };
  }

  /**
   * Full domain verification
   */
  async verifyDomain(domain, claimedBrand = null) {
    const results = {
      domain,
      timestamp: new Date().toISOString(),
      checks: {}
    };

    // Run all checks in parallel
    const [spf, dmarc, mx, exists, patterns] = await Promise.all([
      this.checkSPF(domain),
      this.checkDMARC(domain),
      this.checkMX(domain),
      this.checkDomainExists(domain),
      Promise.resolve(this.checkSuspiciousPatterns(domain))
    ]);

    results.checks = { spf, dmarc, mx, exists, patterns };

    // Brand verification
    if (claimedBrand) {
      results.brandVerification = this.verifyBrandDomain(domain, claimedBrand);
    }

    // Calculate trust score
    let trustScore = 50; // Start neutral

    if (spf.exists) trustScore += 15;
    if (spf.hasStrict) trustScore += 5;
    if (dmarc.exists) trustScore += 15;
    if (dmarc.policy === 'reject') trustScore += 5;
    if (mx.exists) trustScore += 10;

    if (patterns.suspicious) trustScore -= patterns.issues.length * 15;
    if (results.brandVerification?.verified === false) trustScore -= 40;
    if (results.brandVerification?.verified === true) trustScore += 20;

    results.trustScore = Math.max(0, Math.min(100, trustScore));
    results.trustLevel = trustScore >= 70 ? 'high' : trustScore >= 40 ? 'medium' : 'low';

    return results;
  }
}

export default new DomainChecker();
export { DomainChecker };
