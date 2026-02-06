/**
 * Threat Intelligence Module
 * Integrates multiple threat feeds and APIs for comprehensive URL/domain analysis
 * 
 * Features:
 * - VirusTotal API (70+ antivirus engines)
 * - WHOIS Lookup (domain age check)
 * - PhishTank Database
 * - Expanded local blacklist
 * - Custom phishing patterns
 */

import https from 'https';
import http from 'http';
import dns from 'dns';
import { promisify } from 'util';

const dnsResolve = promisify(dns.resolve);

class ThreatIntelligence {
  constructor() {
    // API Keys (from environment)
    this.virusTotalApiKey = null;
    this.phishTankApiKey = null;

    // Expanded Blacklist - Known phishing domains and patterns
    this.blacklistedDomains = [
      // PayPal phishing
      'paypal-secure-login.xyz',
      'paypal-verify.tk',
      'paypa1-login.com',
      'paypal-update.ml',
      'secure-paypal.cf',
      'paypal-confirm.ga',
      'paypal-security.gq',
      
      // Amazon phishing
      'amazon-verify.tk',
      'amaz0n-login.xyz',
      'amazon-security.ml',
      'amazon-update.cf',
      'amazon-prime-verify.ga',
      
      // Banking phishing
      'chase-secure.xyz',
      'bankofamerica-verify.tk',
      'wellsfargo-login.ml',
      'citibank-update.cf',
      
      // Microsoft phishing
      'microsoft-verify.xyz',
      'office365-login.tk',
      'outlook-security.ml',
      'microsoft-update.cf',
      'teams-verify.ga',
      
      // Google phishing
      'google-verify.xyz',
      'gmail-security.tk',
      'google-account.ml',
      'drive-share.cf',
      
      // Apple phishing
      'apple-verify.xyz',
      'icloud-login.tk',
      'apple-id-update.ml',
      'appstore-verify.cf',
      
      // Netflix phishing
      'netflix-verify.xyz',
      'netflix-update.tk',
      'netflix-billing.ml',
      
      // Social Media phishing
      'facebook-verify.xyz',
      'instagram-login.tk',
      'twitter-security.ml',
      'linkedin-update.cf',
      'tiktok-verify.ga',
      
      // Cryptocurrency scams
      'coinbase-verify.xyz',
      'binance-login.tk',
      'crypto-wallet.ml',
      'bitcoin-giveaway.cf',
      
      // Generic phishing patterns
      'secure-login-verify.com',
      'account-update-required.com',
      'verify-your-account.xyz',
      'urgent-security-update.com',
      'confirm-identity.tk'
    ];

    // Suspicious URL patterns (regex)
    this.suspiciousPatterns = [
      // Brand impersonation with variations
      /paypa[l1].*(?:secure|verify|login|update)/i,
      /amaz[o0]n.*(?:secure|verify|login|update)/i,
      /g[o0]{2}gle.*(?:secure|verify|login|update)/i,
      /micr[o0]s[o0]ft.*(?:secure|verify|login|update)/i,
      /faceb[o0]{2}k.*(?:secure|verify|login|update)/i,
      /app[l1]e.*(?:secure|verify|login|update)/i,
      /netf[l1]ix.*(?:secure|verify|login|update)/i,
      
      // Urgency patterns
      /urgent.*(?:verify|update|confirm|action)/i,
      /immediate.*(?:action|verify|update)/i,
      /account.*(?:suspended|locked|limited)/i,
      /(?:verify|confirm).*(?:identity|account|email)/i,
      
      // Credential harvesting
      /(?:login|signin|sign-in).*(?:verify|secure|update)/i,
      /(?:password|credential).*(?:reset|update|expire)/i,
      /(?:billing|payment).*(?:update|verify|confirm)/i,
      
      // Prize/lottery scams
      /(?:winner|won|prize|lottery|giveaway)/i,
      /(?:claim|collect).*(?:prize|reward|gift)/i,
      
      // Tech support scams
      /(?:virus|malware|infected).*(?:detected|found|alert)/i,
      /(?:call|contact).*(?:support|helpdesk|technician)/i
    ];

    // Known legitimate domains (whitelist)
    this.whitelistedDomains = [
      'google.com', 'www.google.com', 'accounts.google.com',
      'facebook.com', 'www.facebook.com',
      'amazon.com', 'www.amazon.com',
      'apple.com', 'www.apple.com', 'icloud.com',
      'microsoft.com', 'www.microsoft.com', 'outlook.com', 'office.com',
      'paypal.com', 'www.paypal.com',
      'netflix.com', 'www.netflix.com',
      'twitter.com', 'x.com',
      'instagram.com', 'www.instagram.com',
      'linkedin.com', 'www.linkedin.com',
      'github.com', 'www.github.com',
      'stackoverflow.com',
      'youtube.com', 'www.youtube.com',
      'wikipedia.org', 'en.wikipedia.org',
      'reddit.com', 'www.reddit.com'
    ];

    // Malicious TLDs (high risk)
    this.highRiskTLDs = [
      '.tk', '.ml', '.ga', '.cf', '.gq',  // Free TLDs (heavily abused)
      '.xyz', '.top', '.click', '.link', '.work',
      '.buzz', '.live', '.online', '.site', '.club',
      '.icu', '.vip', '.win', '.loan', '.racing',
      '.download', '.stream', '.party', '.review', '.trade'
    ];

    // PhishTank cache (in-memory)
    this.phishTankCache = new Map();
    this.phishTankCacheExpiry = 3600000; // 1 hour
  }

  /**
   * Get API keys dynamically (after dotenv loads)
   */
  getVirusTotalApiKey() {
    return process.env.VIRUSTOTAL_API_KEY || null;
  }

  getPhishTankApiKey() {
    return process.env.PHISHTANK_API_KEY || null;
  }

  /**
   * Main analysis function - combines all threat intelligence sources
   */
  async analyzeURL(url) {
    const results = {
      url,
      timestamp: new Date().toISOString(),
      sources: [],
      threats: [],
      riskScore: 0,
      riskFactors: [],
      details: {}
    };

    try {
      const parsedURL = new URL(url.startsWith('http') ? url : `https://${url}`);
      const hostname = parsedURL.hostname;
      const domain = this.extractBaseDomain(hostname);

      // Run all checks in parallel
      const [
        blacklistResult,
        patternResult,
        whoisResult,
        virusTotalResult,
        phishTankResult
      ] = await Promise.all([
        this.checkBlacklist(hostname, url),
        this.checkSuspiciousPatterns(url, hostname),
        this.checkWHOIS(domain),
        this.checkVirusTotal(url),
        this.checkPhishTank(url)
      ]);

      // Aggregate results
      results.details = {
        blacklist: blacklistResult,
        patterns: patternResult,
        whois: whoisResult,
        virusTotal: virusTotalResult,
        phishTank: phishTankResult
      };

      // Calculate risk score
      let riskScore = 0;

      // Blacklist check (immediate high risk)
      if (blacklistResult.blacklisted) {
        riskScore += 50;
        results.threats.push({ source: 'Local Blacklist', type: 'BLACKLISTED' });
        results.riskFactors.push('Domain is blacklisted');
        results.sources.push('Local Blacklist');
      }

      // Pattern check
      if (patternResult.suspicious) {
        riskScore += patternResult.matches.length * 15;
        results.riskFactors.push(...patternResult.matches.map(m => `Suspicious pattern: ${m}`));
        results.sources.push('Pattern Analysis');
      }

      // WHOIS check (domain age)
      if (whoisResult.available) {
        if (whoisResult.ageInDays !== null) {
          if (whoisResult.ageInDays < 30) {
            riskScore += 30;
            results.riskFactors.push(`Domain registered ${whoisResult.ageInDays} days ago (very new)`);
          } else if (whoisResult.ageInDays < 90) {
            riskScore += 20;
            results.riskFactors.push(`Domain registered ${whoisResult.ageInDays} days ago (new)`);
          } else if (whoisResult.ageInDays < 365) {
            riskScore += 10;
            results.riskFactors.push(`Domain less than 1 year old`);
          }
        }
        results.sources.push('WHOIS Lookup');
      }

      // VirusTotal check
      if (virusTotalResult.checked) {
        results.sources.push('VirusTotal');
        if (virusTotalResult.malicious > 0) {
          riskScore += Math.min(virusTotalResult.malicious * 10, 50);
          results.threats.push({
            source: 'VirusTotal',
            type: 'MALICIOUS',
            detections: virusTotalResult.malicious,
            total: virusTotalResult.total
          });
          results.riskFactors.push(`Flagged by ${virusTotalResult.malicious}/${virusTotalResult.total} security vendors`);
        }
        if (virusTotalResult.suspicious > 0) {
          riskScore += virusTotalResult.suspicious * 5;
          results.riskFactors.push(`Marked suspicious by ${virusTotalResult.suspicious} vendors`);
        }
      }

      // PhishTank check
      if (phishTankResult.checked) {
        results.sources.push('PhishTank');
        if (phishTankResult.isPhishing) {
          riskScore += 50;
          results.threats.push({ source: 'PhishTank', type: 'PHISHING', verified: phishTankResult.verified });
          results.riskFactors.push('Listed in PhishTank database');
        }
      }

      // TLD risk check
      const tldRisk = this.checkTLDRisk(hostname);
      if (tldRisk.highRisk) {
        riskScore += 15;
        results.riskFactors.push(`High-risk TLD: ${tldRisk.tld}`);
      }

      // Whitelist bonus (reduces risk and clears risk factors for trusted domains)
      const isWhitelisted = this.whitelistedDomains.includes(hostname) || this.whitelistedDomains.includes(domain);
      if (isWhitelisted) {
        riskScore = Math.max(0, riskScore - 50);
        // For whitelisted domains, move this to safety indicators, not risk factors
        if (!results.safetyIndicators) results.safetyIndicators = [];
        results.safetyIndicators.push('Domain is whitelisted (trusted)');
        // Clear misleading risk factors for trusted domains
        results.riskFactors = results.riskFactors.filter(f => 
          !f.includes('No SPF') && 
          !f.includes('No DMARC') && 
          !f.includes('Domain registered') &&
          !f.includes('whitelisted')
        );
      }

      results.riskScore = Math.min(100, Math.max(0, riskScore));
      results.isPhishing = results.riskScore >= 50;
      results.riskLevel = results.riskScore >= 70 ? 'critical' : 
                          results.riskScore >= 50 ? 'high' : 
                          results.riskScore >= 30 ? 'medium' : 'low';

      return results;

    } catch (error) {
      console.error('Threat intelligence error:', error);
      return {
        ...results,
        error: error.message,
        riskScore: 30,
        riskLevel: 'medium'
      };
    }
  }

  /**
   * Check against local blacklist
   */
  checkBlacklist(hostname, url) {
    const hostnameClean = hostname.toLowerCase();
    const urlLower = url.toLowerCase();

    // Check exact domain match
    for (const blocked of this.blacklistedDomains) {
      if (hostnameClean === blocked || hostnameClean.endsWith(`.${blocked}`)) {
        return { blacklisted: true, match: blocked, type: 'exact' };
      }
      // Check if blocked domain is in URL
      if (urlLower.includes(blocked)) {
        return { blacklisted: true, match: blocked, type: 'contains' };
      }
    }

    return { blacklisted: false };
  }

  /**
   * Check URL against suspicious patterns
   */
  checkSuspiciousPatterns(url, hostname) {
    const matches = [];
    const combined = `${url} ${hostname}`;

    for (const pattern of this.suspiciousPatterns) {
      if (pattern.test(combined)) {
        matches.push(pattern.source.substring(0, 50));
      }
    }

    return {
      suspicious: matches.length > 0,
      matches: [...new Set(matches)].slice(0, 5) // Limit to 5 unique matches
    };
  }

  /**
   * WHOIS Lookup - Check domain age
   */
  async checkWHOIS(domain) {
    try {
      // Try RDAP first
      let rdapResult = await this.queryRDAP(domain);
      
      // If RDAP fails, try WhoisXML free API (limited requests)
      if (!rdapResult.registrationDate) {
        rdapResult = await this.queryWhoisXML(domain);
      }
      
      if (rdapResult.registrationDate) {
        const regDate = new Date(rdapResult.registrationDate);
        const now = new Date();
        const ageInDays = Math.floor((now - regDate) / (1000 * 60 * 60 * 24));
        
        return {
          available: true,
          domain,
          registrationDate: rdapResult.registrationDate,
          ageInDays,
          ageDescription: this.describeAge(ageInDays),
          registrar: rdapResult.registrar
        };
      }

      return { available: false, domain, reason: 'No registration data' };
    } catch (error) {
      return { available: false, domain, error: error.message };
    }
  }

  /**
   * Query WhoisXML API (free tier - 500 queries/month)
   */
  async queryWhoisXML(domain) {
    return new Promise((resolve) => {
      // Free API endpoint (limited but works)
      const req = https.request({
        hostname: 'whois.freeaitools.xyz',
        path: `/api/whois?domain=${encodeURIComponent(domain)}`,
        method: 'GET',
        timeout: 5000,
        headers: {
          'User-Agent': 'PhishNet/1.0'
        }
      }, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          try {
            const json = JSON.parse(data);
            const createdDate = json.created_date || json.creation_date || json.createdDate;
            resolve({
              registrationDate: createdDate || null,
              registrar: json.registrar || null
            });
          } catch (e) {
            resolve({ registrationDate: null, registrar: null });
          }
        });
      });

      req.on('error', () => resolve({ registrationDate: null, registrar: null }));
      req.on('timeout', () => {
        req.destroy();
        resolve({ registrationDate: null, registrar: null });
      });

      req.end();
    });
  }

  /**
   * Query RDAP for domain information - improved with fallback
   */
  async queryRDAP(domain) {
    // Try rdap.org first (universal bootstrap)
    const servers = [
      { hostname: 'rdap.org', path: `/domain/${domain}` },
      { hostname: 'rdap.verisign.com', path: `/rdap/domain/${domain}` },
      { hostname: 'www.rdap.net', path: `/domain/${domain}` }
    ];

    for (const server of servers) {
      try {
        const result = await this.tryRDAPServer(server.hostname, server.path);
        if (result.registrationDate) {
          return result;
        }
      } catch (e) {
        // Try next server
        continue;
      }
    }

    return { registrationDate: null, registrar: null };
  }

  /**
   * Try a single RDAP server
   */
  tryRDAPServer(hostname, path) {
    return new Promise((resolve) => {
      const options = {
        hostname,
        path,
        method: 'GET',
        timeout: 5000,
        headers: {
          'Accept': 'application/rdap+json',
          'User-Agent': 'PhishNet/1.0'
        }
      };

      const req = https.request(options, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          try {
            const json = JSON.parse(data);
            
            // Extract registration date from events
            let registrationDate = null;
            let registrar = null;

            if (json.events) {
              const regEvent = json.events.find(e => e.eventAction === 'registration');
              if (regEvent) {
                registrationDate = regEvent.eventDate;
              }
            }

            if (json.entities) {
              const registrarEntity = json.entities.find(e => 
                e.roles && e.roles.includes('registrar')
              );
              if (registrarEntity && registrarEntity.vcardArray) {
                // Parse vCard for registrar name
                const vcard = registrarEntity.vcardArray[1];
                const fnEntry = vcard?.find(v => v[0] === 'fn');
                registrar = fnEntry ? fnEntry[3] : null;
              }
            }

            resolve({ registrationDate, registrar });
          } catch (e) {
            resolve({ registrationDate: null, registrar: null });
          }
        });
      });

      req.on('error', () => resolve({ registrationDate: null, registrar: null }));
      req.on('timeout', () => {
        req.destroy();
        resolve({ registrationDate: null, registrar: null });
      });

      req.end();
    });
  }

  /**
   * Describe domain age in human-readable format
   */
  describeAge(days) {
    if (days < 7) return 'Less than a week old (VERY SUSPICIOUS)';
    if (days < 30) return 'Less than a month old (SUSPICIOUS)';
    if (days < 90) return 'Less than 3 months old (CAUTION)';
    if (days < 365) return 'Less than 1 year old';
    if (days < 730) return '1-2 years old';
    if (days < 1825) return '2-5 years old';
    return 'Over 5 years old (Established)';
  }

  /**
   * VirusTotal API check
   */
  async checkVirusTotal(url) {
    const apiKey = this.getVirusTotalApiKey();
    
    if (!apiKey) {
      return { checked: false, reason: 'No API key' };
    }

    try {
      // First, submit URL for analysis
      const urlId = Buffer.from(url).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
      
      return new Promise((resolve) => {
        const req = https.request({
          hostname: 'www.virustotal.com',
          path: `/api/v3/urls/${urlId}`,
          method: 'GET',
          headers: {
            'x-apikey': apiKey,
            'Accept': 'application/json'
          },
          timeout: 10000
        }, (res) => {
          let data = '';
          res.on('data', chunk => data += chunk);
          res.on('end', () => {
            try {
              const json = JSON.parse(data);
              
              if (json.data?.attributes?.last_analysis_stats) {
                const stats = json.data.attributes.last_analysis_stats;
                resolve({
                  checked: true,
                  malicious: stats.malicious || 0,
                  suspicious: stats.suspicious || 0,
                  harmless: stats.harmless || 0,
                  undetected: stats.undetected || 0,
                  total: (stats.malicious || 0) + (stats.suspicious || 0) + (stats.harmless || 0) + (stats.undetected || 0),
                  lastAnalysis: json.data.attributes.last_analysis_date
                });
              } else if (json.error) {
                // URL not found in VT, submit for scanning
                resolve({ checked: true, malicious: 0, suspicious: 0, total: 0, note: 'URL not previously scanned' });
              } else {
                resolve({ checked: true, malicious: 0, suspicious: 0, total: 0 });
              }
            } catch (e) {
              resolve({ checked: false, error: e.message });
            }
          });
        });

        req.on('error', (e) => resolve({ checked: false, error: e.message }));
        req.on('timeout', () => {
          req.destroy();
          resolve({ checked: false, error: 'Timeout' });
        });

        req.end();
      });
    } catch (error) {
      return { checked: false, error: error.message };
    }
  }

  /**
   * PhishTank API check
   */
  async checkPhishTank(url) {
    // Check cache first
    const cached = this.phishTankCache.get(url);
    if (cached && Date.now() - cached.timestamp < this.phishTankCacheExpiry) {
      return cached.result;
    }

    try {
      const apiKey = this.getPhishTankApiKey();
      
      return new Promise((resolve) => {
        const postData = `url=${encodeURIComponent(url)}&format=json${apiKey ? `&app_key=${apiKey}` : ''}`;
        
        const req = https.request({
          hostname: 'checkurl.phishtank.com',
          path: '/checkurl/',
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': Buffer.byteLength(postData),
            'User-Agent': 'phishtank/PhishNet'
          },
          timeout: 10000
        }, (res) => {
          let data = '';
          res.on('data', chunk => data += chunk);
          res.on('end', () => {
            try {
              const json = JSON.parse(data);
              const result = {
                checked: true,
                isPhishing: json.results?.in_database && json.results?.valid,
                verified: json.results?.verified,
                verifiedAt: json.results?.verified_at,
                phishId: json.results?.phish_id
              };
              
              // Cache result
              this.phishTankCache.set(url, { result, timestamp: Date.now() });
              
              resolve(result);
            } catch (e) {
              resolve({ checked: false, error: e.message });
            }
          });
        });

        req.on('error', () => resolve({ checked: false, error: 'Connection failed' }));
        req.on('timeout', () => {
          req.destroy();
          resolve({ checked: false, error: 'Timeout' });
        });

        req.write(postData);
        req.end();
      });
    } catch (error) {
      return { checked: false, error: error.message };
    }
  }

  /**
   * Check TLD risk level
   */
  checkTLDRisk(hostname) {
    const tld = '.' + hostname.split('.').pop();
    return {
      tld,
      highRisk: this.highRiskTLDs.includes(tld.toLowerCase())
    };
  }

  /**
   * Extract base domain from hostname
   */
  extractBaseDomain(hostname) {
    const parts = hostname.split('.');
    if (parts.length >= 2) {
      return parts.slice(-2).join('.');
    }
    return hostname;
  }

  /**
   * Check if domain is whitelisted
   */
  isWhitelisted(hostname) {
    const domain = this.extractBaseDomain(hostname);
    return this.whitelistedDomains.includes(hostname) || 
           this.whitelistedDomains.includes(domain);
  }

  /**
   * Add domain to blacklist
   */
  addToBlacklist(domain) {
    if (!this.blacklistedDomains.includes(domain.toLowerCase())) {
      this.blacklistedDomains.push(domain.toLowerCase());
      return true;
    }
    return false;
  }

  /**
   * Get statistics
   */
  getStats() {
    return {
      blacklistedDomains: this.blacklistedDomains.length,
      suspiciousPatterns: this.suspiciousPatterns.length,
      whitelistedDomains: this.whitelistedDomains.length,
      highRiskTLDs: this.highRiskTLDs.length,
      phishTankCacheSize: this.phishTankCache.size
    };
  }
}

export default new ThreatIntelligence();
export { ThreatIntelligence };
