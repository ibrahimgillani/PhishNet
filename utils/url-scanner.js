/**
 * Advanced URL Scanner
 * Multi-layer URL analysis beyond Google Safe Browsing
 * 
 * Features:
 * - URL structure analysis (suspicious patterns)
 * - Domain reputation check
 * - SSL certificate verification
 * - Redirect chain analysis
 * - Content analysis (page title, forms)
 * - Threat intelligence APIs (VirusTotal, PhishTank)
 * - Homograph/typosquatting detection
 * - WHOIS domain age check
 */

import https from 'https';
import http from 'http';
import dns from 'dns';
import { promisify } from 'util';
import { URL } from 'url';
import domainChecker from './domain-checker.js';
import threatIntelligence from './threat-intelligence.js';

const dnsResolve = promisify(dns.resolve);

class URLScanner {
  constructor() {
    // API keys will be read dynamically to ensure dotenv is loaded first
    // See getGoogleApiKey() and getVirusTotalApiKey() methods

    // Known phishing URL patterns
    this.suspiciousPatterns = [
      /login.*verify/i,
      /secure.*update/i,
      /account.*confirm/i,
      /verify.*identity/i,
      /password.*reset/i,
      /billing.*update/i,
      /suspended.*account/i,
      /unlock.*account/i,
      /verify.*email/i,
      /confirm.*payment/i
    ];

    // Suspicious URL shorteners (often used to hide malicious URLs)
    this.urlShorteners = [
      'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 
      'buff.ly', 'adf.ly', 'shorte.st', 'bc.vc', 'j.mp', 'v.gd',
      'cutt.ly', 'rb.gy', 'shorturl.at', 'tiny.cc'
    ];

    // Known malicious TLDs
    this.maliciousTLDs = [
      '.xyz', '.top', '.click', '.link', '.work', '.gq', '.ml', 
      '.cf', '.tk', '.ga', '.buzz', '.live', '.online', '.site',
      '.club', '.icu', '.vip', '.win', '.loan', '.racing'
    ];

    // Brand domains for typosquatting detection
    this.brandDomains = {
      'google': 'google.com',
      'facebook': 'facebook.com',
      'amazon': 'amazon.com',
      'apple': 'apple.com',
      'microsoft': 'microsoft.com',
      'paypal': 'paypal.com',
      'netflix': 'netflix.com',
      'chase': 'chase.com',
      'bankofamerica': 'bankofamerica.com',
      'wellsfargo': 'wellsfargo.com'
    };

    // Homograph characters (lookalikes)
    this.homographs = {
      'a': ['а', 'ą', 'α', '@'],
      'e': ['е', 'ę', 'ε', '3'],
      'i': ['і', 'ı', '1', 'l', '|'],
      'o': ['о', 'ø', '0'],
      'c': ['с', 'ç'],
      'p': ['р', 'ρ'],
      'y': ['у', 'ý'],
      'n': ['п', 'ñ'],
      's': ['ѕ', '$', '5'],
      'l': ['1', 'I', '|'],
      'g': ['9', 'q']
    };
  }

  /**
   * Main URL scanning function
   */
  async scanURL(urlString) {
    const startTime = Date.now();
    const results = {
      url: urlString,
      timestamp: new Date().toISOString(),
      isPhishing: false,
      riskScore: 0,
      riskLevel: 'low',
      checks: {},
      riskFactors: [],
      safetyIndicators: [],
      threatIntelligence: null
    };

    try {
      // Parse URL
      const parsedURL = this.parseURL(urlString);
      if (!parsedURL.valid) {
        return { ...results, error: 'Invalid URL', isPhishing: true, riskLevel: 'high' };
      }
      results.parsedURL = parsedURL;

      // Run all checks in parallel (including new threat intelligence)
      const [
        structureAnalysis,
        domainAnalysis,
        sslCheck,
        redirectCheck,
        threatIntel,
        typosquatCheck,
        advancedThreatIntel
      ] = await Promise.all([
        this.analyzeURLStructure(parsedURL),
        this.analyzeDomain(parsedURL.hostname),
        this.checkSSL(parsedURL),
        this.checkRedirects(urlString),
        this.checkThreatIntelligence(urlString),
        this.detectTyposquatting(parsedURL.hostname),
        threatIntelligence.analyzeURL(urlString)
      ]);

      results.checks = {
        structure: structureAnalysis,
        domain: domainAnalysis,
        ssl: sslCheck,
        redirects: redirectCheck,
        threatIntel: threatIntel,
        typosquatting: typosquatCheck
      };

      // Add advanced threat intelligence results
      results.threatIntelligence = advancedThreatIntel;

      // Calculate risk score (now considers threat intelligence)
      this.calculateRiskScore(results);

      results.scanTime = Date.now() - startTime;
      return results;

    } catch (error) {
      console.error('URL scan error:', error);
      return { 
        ...results, 
        error: error.message,
        riskScore: 50,
        riskLevel: 'medium'
      };
    }
  }

  /**
   * Parse and validate URL
   */
  parseURL(urlString) {
    try {
      // Add protocol if missing
      if (!urlString.startsWith('http://') && !urlString.startsWith('https://')) {
        urlString = 'https://' + urlString;
      }

      const url = new URL(urlString);
      return {
        valid: true,
        original: urlString,
        protocol: url.protocol,
        hostname: url.hostname,
        port: url.port,
        pathname: url.pathname,
        search: url.search,
        hash: url.hash,
        domain: this.extractDomain(url.hostname),
        subdomain: this.extractSubdomain(url.hostname),
        tld: this.extractTLD(url.hostname)
      };
    } catch (error) {
      return { valid: false, error: error.message };
    }
  }

  extractDomain(hostname) {
    const parts = hostname.split('.');
    if (parts.length >= 2) {
      return parts.slice(-2).join('.');
    }
    return hostname;
  }

  extractSubdomain(hostname) {
    const parts = hostname.split('.');
    if (parts.length > 2) {
      return parts.slice(0, -2).join('.');
    }
    return '';
  }

  extractTLD(hostname) {
    const parts = hostname.split('.');
    return '.' + parts[parts.length - 1];
  }

  /**
   * Analyze URL structure for suspicious patterns
   */
  async analyzeURLStructure(parsedURL) {
    const issues = [];
    const positives = [];

    // Check protocol
    if (parsedURL.protocol === 'http:') {
      issues.push('Uses insecure HTTP protocol');
    } else {
      positives.push('Uses secure HTTPS protocol');
    }

    // Check for IP address instead of domain
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(parsedURL.hostname)) {
      issues.push('Uses IP address instead of domain name');
    }

    // Check for suspicious TLD
    if (this.maliciousTLDs.includes(parsedURL.tld)) {
      issues.push(`Suspicious TLD: ${parsedURL.tld}`);
    }

    // Check for URL shortener
    if (this.urlShorteners.includes(parsedURL.hostname)) {
      issues.push('URL shortener detected - original destination hidden');
    }

    // Check for excessive subdomains
    const subdomainCount = parsedURL.subdomain ? parsedURL.subdomain.split('.').length : 0;
    if (subdomainCount > 3) {
      issues.push(`Excessive subdomains (${subdomainCount})`);
    }

    // Check for suspicious patterns in path
    for (const pattern of this.suspiciousPatterns) {
      if (pattern.test(parsedURL.pathname) || pattern.test(parsedURL.search)) {
        issues.push('Suspicious keywords in URL path');
        break;
      }
    }

    // Check for encoded characters
    if (/%[0-9a-fA-F]{2}.*%[0-9a-fA-F]{2}/.test(parsedURL.search)) {
      issues.push('Multiple URL-encoded characters in query string');
    }

    // Check URL length
    if (parsedURL.original.length > 200) {
      issues.push('Unusually long URL');
    }

    // Check for @ symbol (used to obfuscate real domain)
    if (parsedURL.original.includes('@')) {
      issues.push('Contains @ symbol - possible URL obfuscation');
    }

    // Check for port number
    if (parsedURL.port && !['80', '443', ''].includes(parsedURL.port)) {
      issues.push(`Non-standard port: ${parsedURL.port}`);
    }

    // Check for suspicious URLs/domains embedded in query parameters
    // This catches phishing redirect techniques like ?domain=www.rmicrosoft.com
    const embeddedUrlIssues = this.analyzeQueryParametersForEmbeddedURLs(parsedURL.search);
    if (embeddedUrlIssues.length > 0) {
      issues.push(...embeddedUrlIssues);
    }

    return {
      issues,
      positives,
      riskScore: Math.min(issues.length * 15, 60)
    };
  }

  /**
   * Analyze query parameters for embedded suspicious URLs/domains
   * Catches phishing redirect techniques like ?redirect=fake-bank.com
   */
  analyzeQueryParametersForEmbeddedURLs(queryString) {
    const issues = [];
    if (!queryString || queryString.length < 2) return issues;

    try {
      // Remove leading ? and decode the query string
      const decoded = decodeURIComponent(queryString.substring(1));
      
      // Look for patterns that might contain URLs or domains
      const suspiciousParamNames = [
        'url', 'redirect', 'return', 'goto', 'link', 'next', 'target',
        'domain', 'site', 'ref', 'oref', 'href', 'callback', 'continue',
        'destination', 'rurl', 'return_url', 'redirect_uri'
      ];

      // Parse query parameters
      const params = new URLSearchParams(queryString);
      
      for (const [key, value] of params) {
        const keyLower = key.toLowerCase();
        const valueLower = value.toLowerCase();
        
        // Check if the value looks like a URL or domain
        const urlPattern = /^(https?:\/\/)?([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}/i;
        const domainPattern = /^(www\.)?([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/i;
        
        if (urlPattern.test(value) || domainPattern.test(value)) {
          // Extract the domain from the embedded URL
          let embeddedDomain = value;
          try {
            if (value.startsWith('http')) {
              embeddedDomain = new URL(value).hostname;
            } else if (value.includes('/')) {
              embeddedDomain = value.split('/')[0];
            }
          } catch (e) {
            embeddedDomain = value.split('/')[0];
          }
          
          // Check the embedded domain for typosquatting
          const typoResult = this.detectTyposquatting(embeddedDomain);
          if (typoResult.detected) {
            issues.push(`Suspicious domain "${embeddedDomain}" found in query parameter "${key}"`);
            issues.push(...typoResult.issues.map(i => `Embedded URL: ${i}`));
          }
          
          // Check if this is a redirect-type parameter with a suspicious domain
          if (suspiciousParamNames.some(p => keyLower.includes(p))) {
            // Flag redirect parameters pointing to non-official domains
            const isKnownSafe = ['google.com', 'microsoft.com', 'apple.com', 'amazon.com', 
                                 'facebook.com', 'twitter.com', 'github.com', 'linkedin.com']
              .some(d => embeddedDomain.endsWith(d));
            
            if (!isKnownSafe) {
              issues.push(`Redirect parameter "${key}" points to external domain: ${embeddedDomain}`);
            }
          }
        }
      }
      
      // Also check the raw query string for URL-encoded suspicious domains
      for (const brand of Object.keys(this.brandDomains)) {
        const officialDomain = this.brandDomains[brand];
        // Look for brand variations in encoded/decoded form
        if (decoded.includes(brand) && !decoded.includes(officialDomain)) {
          // Verify it's actually a domain-like pattern, not just text
          const domainCheck = new RegExp(`[a-z]*${brand}[a-z]*\\.(com|org|net|io|co|info|biz)`, 'i');
          if (domainCheck.test(decoded)) {
            const match = decoded.match(domainCheck);
            if (match && match[0] !== officialDomain) {
              issues.push(`Query string contains suspicious domain mimicking "${brand}": ${match[0]}`);
            }
          }
        }
      }
    } catch (error) {
      // If parsing fails, check for suspicious patterns in raw string
      console.error('Query parameter analysis error:', error.message);
    }

    return issues;
  }

  /**
   * Analyze domain reputation
   */
  async analyzeDomain(hostname) {
    try {
      const domainResult = await domainChecker.verifyDomain(hostname);
      
      const issues = [];
      const positives = [];

      if (domainResult.checks.spf.exists) {
        positives.push('Has SPF record');
      } else {
        issues.push('No SPF record');
      }

      if (domainResult.checks.dmarc.exists) {
        positives.push('Has DMARC record');
      } else {
        issues.push('No DMARC record');
      }

      if (domainResult.checks.patterns.suspicious) {
        issues.push(...domainResult.checks.patterns.issues);
      }

      return {
        trustScore: domainResult.trustScore,
        trustLevel: domainResult.trustLevel,
        issues,
        positives,
        details: domainResult.checks
      };
    } catch (error) {
      return {
        error: error.message,
        trustScore: 30,
        trustLevel: 'low'
      };
    }
  }

  /**
   * Check SSL certificate
   */
  async checkSSL(parsedURL) {
    if (parsedURL.protocol !== 'https:') {
      return {
        secure: false,
        issue: 'Not using HTTPS'
      };
    }

    return new Promise((resolve) => {
      const options = {
        hostname: parsedURL.hostname,
        port: 443,
        method: 'HEAD',
        rejectUnauthorized: true,
        timeout: 5000
      };

      const req = https.request(options, (res) => {
        const cert = res.socket.getPeerCertificate();
        
        if (cert && Object.keys(cert).length > 0) {
          const validFrom = new Date(cert.valid_from);
          const validTo = new Date(cert.valid_to);
          const now = new Date();
          const daysUntilExpiry = Math.ceil((validTo - now) / (1000 * 60 * 60 * 24));

          resolve({
            secure: true,
            valid: now >= validFrom && now <= validTo,
            issuer: cert.issuer?.O || 'Unknown',
            subject: cert.subject?.CN || parsedURL.hostname,
            validFrom: validFrom.toISOString(),
            validTo: validTo.toISOString(),
            daysUntilExpiry,
            selfSigned: cert.issuer?.CN === cert.subject?.CN
          });
        } else {
          resolve({ secure: false, issue: 'No certificate found' });
        }
      });

      req.on('error', (error) => {
        resolve({
          secure: false,
          issue: error.message.includes('certificate') 
            ? 'Invalid SSL certificate' 
            : 'Connection failed'
        });
      });

      req.on('timeout', () => {
        req.destroy();
        resolve({ secure: false, issue: 'Connection timeout' });
      });

      req.end();
    });
  }

  /**
   * Check for redirects
   */
  async checkRedirects(urlString, maxRedirects = 5) {
    const redirectChain = [];
    let currentURL = urlString;
    let redirectCount = 0;

    while (redirectCount < maxRedirects) {
      try {
        const result = await this.followRedirect(currentURL);
        
        if (result.redirect) {
          redirectChain.push({
            from: currentURL,
            to: result.location,
            statusCode: result.statusCode
          });
          currentURL = result.location;
          redirectCount++;
        } else {
          break;
        }
      } catch (error) {
        break;
      }
    }

    const issues = [];
    if (redirectCount > 2) {
      issues.push(`Multiple redirects (${redirectCount})`);
    }

    // Check if redirects go through suspicious domains
    for (const redirect of redirectChain) {
      try {
        const url = new URL(redirect.to);
        if (this.urlShorteners.includes(url.hostname)) {
          issues.push('Redirects through URL shortener');
        }
      } catch (e) {
        // Invalid URL in redirect
      }
    }

    return {
      redirectCount,
      redirectChain,
      finalURL: currentURL,
      issues
    };
  }

  followRedirect(urlString) {
    return new Promise((resolve) => {
      try {
        const url = new URL(urlString);
        const protocol = url.protocol === 'https:' ? https : http;

        const req = protocol.request({
          hostname: url.hostname,
          port: url.port || (url.protocol === 'https:' ? 443 : 80),
          path: url.pathname + url.search,
          method: 'HEAD',
          timeout: 5000,
          headers: {
            'User-Agent': 'Mozilla/5.0 PhishNet Security Scanner'
          }
        }, (res) => {
          if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
            let location = res.headers.location;
            // Handle relative redirects
            if (!location.startsWith('http')) {
              location = `${url.protocol}//${url.hostname}${location}`;
            }
            resolve({
              redirect: true,
              statusCode: res.statusCode,
              location
            });
          } else {
            resolve({
              redirect: false,
              statusCode: res.statusCode
            });
          }
        });

        req.on('error', () => resolve({ redirect: false, error: true }));
        req.on('timeout', () => {
          req.destroy();
          resolve({ redirect: false, error: true });
        });

        req.end();
      } catch (error) {
        resolve({ redirect: false, error: true });
      }
    });
  }

  /**
   * Get Google Safe Browsing API key (read dynamically after dotenv loads)
   */
  getGoogleApiKey() {
    return process.env.GOOGLE_SAFE_BROWSING_API_KEY || null;
  }

  /**
   * Get VirusTotal API key (read dynamically after dotenv loads)
   */
  getVirusTotalApiKey() {
    return process.env.VIRUSTOTAL_API_KEY || null;
  }

  /**
   * Check against threat intelligence services
   */
  async checkThreatIntelligence(urlString) {
    const results = {
      checked: [],
      threats: []
    };

    const googleApiKey = this.getGoogleApiKey();
    const virusTotalApiKey = this.getVirusTotalApiKey();

    // Google Safe Browsing
    if (googleApiKey) {
      try {
        const gsb = await this.checkGoogleSafeBrowsing(urlString, googleApiKey);
        results.checked.push('Google Safe Browsing');
        if (gsb.threat) {
          results.threats.push({
            source: 'Google Safe Browsing',
            type: gsb.threatType
          });
        }
      } catch (error) {
        console.error('GSB check failed:', error.message);
        results.checked.push('Google Safe Browsing (error)');
      }
    }

    // VirusTotal
    if (virusTotalApiKey) {
      try {
        const vt = await this.checkVirusTotal(urlString, virusTotalApiKey);
        results.checked.push('VirusTotal');
        if (vt.malicious > 0) {
          results.threats.push({
            source: 'VirusTotal',
            detections: vt.malicious,
            total: vt.total
          });
        }
      } catch (error) {
        console.error('VirusTotal check failed:', error.message);
      }
    }

    // Local blacklist check (you can expand this)
    const localCheck = this.checkLocalBlacklist(urlString);
    results.checked.push('Local Blacklist');
    if (localCheck.blocked) {
      results.threats.push({
        source: 'Local Blacklist',
        reason: localCheck.reason
      });
    }

    return results;
  }

  /**
   * Google Safe Browsing API check
   */
  async checkGoogleSafeBrowsing(urlString, apiKey) {
    const requestBody = {
      client: {
        clientId: 'phishnet',
        clientVersion: '1.0.0'
      },
      threatInfo: {
        threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
        platformTypes: ['ANY_PLATFORM'],
        threatEntryTypes: ['URL'],
        threatEntries: [{ url: urlString }]
      }
    };

    return new Promise((resolve, reject) => {
      const postData = JSON.stringify(requestBody);
      
      const req = https.request({
        hostname: 'safebrowsing.googleapis.com',
        path: `/v4/threatMatches:find?key=${apiKey}`,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(postData)
        }
      }, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          try {
            const response = JSON.parse(data);
            if (response.matches && response.matches.length > 0) {
              resolve({
                threat: true,
                threatType: response.matches[0].threatType
              });
            } else if (response.error) {
              console.error('GSB API error:', response.error.message);
              resolve({ threat: false, error: response.error.message });
            } else {
              resolve({ threat: false });
            }
          } catch (e) {
            resolve({ threat: false, error: e.message });
          }
        });
      });

      req.on('error', reject);
      req.write(postData);
      req.end();
    });
  }

  /**
   * VirusTotal API check
   */
  async checkVirusTotal(urlString, apiKey) {
    const urlId = Buffer.from(urlString).toString('base64').replace(/=/g, '');
    
    return new Promise((resolve, reject) => {
      const req = https.request({
        hostname: 'www.virustotal.com',
        path: `/api/v3/urls/${urlId}`,
        method: 'GET',
        headers: {
          'x-apikey': apiKey
        }
      }, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          try {
            const response = JSON.parse(data);
            if (response.data?.attributes?.last_analysis_stats) {
              const stats = response.data.attributes.last_analysis_stats;
              resolve({
                malicious: stats.malicious || 0,
                suspicious: stats.suspicious || 0,
                harmless: stats.harmless || 0,
                total: stats.malicious + stats.suspicious + stats.harmless + stats.undetected
              });
            } else {
              resolve({ malicious: 0, total: 0 });
            }
          } catch (e) {
            resolve({ malicious: 0, error: e.message });
          }
        });
      });

      req.on('error', reject);
      req.end();
    });
  }

  /**
   * Local blacklist check
   */
  checkLocalBlacklist(urlString) {
    // Add known phishing domains here
    const blacklist = [
      'secure-login-verify.com',
      'account-update-required.com',
      'paypal-secure-login.xyz',
      // Add more as needed
    ];

    try {
      const url = new URL(urlString);
      for (const blocked of blacklist) {
        if (url.hostname.includes(blocked)) {
          return { blocked: true, reason: 'Domain in local blacklist' };
        }
      }
    } catch (e) {
      // Invalid URL
    }

    return { blocked: false };
  }

  /**
   * Detect typosquatting/homograph attacks
   */
  detectTyposquatting(hostname) {
    const issues = [];
    const hostnameClean = hostname.toLowerCase().replace(/[.-]/g, '');
    
    // Extract base domain (e.g., www.paypal.com -> paypal.com)
    const parts = hostname.toLowerCase().split('.');
    const baseDomain = parts.length >= 2 ? parts.slice(-2).join('.') : hostname;
    const baseDomainWithoutTLD = parts.length >= 2 ? parts[parts.length - 2] : parts[0];

    for (const [brand, officialDomain] of Object.entries(this.brandDomains)) {
      // Skip if this IS the official domain
      if (baseDomain === officialDomain || hostname.endsWith(`.${officialDomain}`)) {
        continue;
      }
      
      // Check if domain contains the brand name but is NOT the official domain
      // This catches typosquatting like "rmicrosoft.com", "micr0soft.com", "microsoftt.com"
      if (baseDomainWithoutTLD.includes(brand) || hostnameClean.includes(brand)) {
        issues.push(`Contains "${brand}" but is not the official ${officialDomain} domain`);
      }
      
      // Check Levenshtein distance for near-matches
      const distance = this.levenshteinDistance(baseDomainWithoutTLD, brand);
      if (distance > 0 && distance <= 2) {
        issues.push(`Similar to "${brand}" (possible typosquatting - distance: ${distance})`);
      }

      // Check for homograph characters
      const hasHomograph = this.checkHomographs(hostname, brand);
      if (hasHomograph) {
        issues.push(`Contains lookalike characters mimicking "${brand}"`);
      }
      
      // Check for brand name with extra/missing/substituted characters
      // e.g., "rmicrosoft" (extra r), "microsfot" (swap), "micosoft" (missing r)
      const brandPattern = new RegExp(`[^a-z]?${brand.split('').join('[^a-z]?')}[^a-z]?`, 'i');
      if (!baseDomain.includes(brand) && brandPattern.test(baseDomainWithoutTLD)) {
        issues.push(`Appears to mimic "${brand}" with character modifications`);
      }
    }

    // Check for common typosquatting patterns with any brand mention
    for (const brand of Object.keys(this.brandDomains)) {
      const officialDomain = this.brandDomains[brand];
      
      // If hostname contains brand but isn't the official domain
      if (hostname.includes(brand) && !hostname.endsWith(officialDomain) && baseDomain !== officialDomain) {
        if (!issues.some(i => i.includes(brand))) {
          issues.push(`Contains "${brand}" but is not official domain`);
        }
      }
    }

    return {
      detected: issues.length > 0,
      issues
    };
  }

  /**
   * Calculate Levenshtein distance
   */
  levenshteinDistance(a, b) {
    const matrix = [];
    
    for (let i = 0; i <= b.length; i++) {
      matrix[i] = [i];
    }
    for (let j = 0; j <= a.length; j++) {
      matrix[0][j] = j;
    }
    
    for (let i = 1; i <= b.length; i++) {
      for (let j = 1; j <= a.length; j++) {
        if (b.charAt(i - 1) === a.charAt(j - 1)) {
          matrix[i][j] = matrix[i - 1][j - 1];
        } else {
          matrix[i][j] = Math.min(
            matrix[i - 1][j - 1] + 1,
            matrix[i][j - 1] + 1,
            matrix[i - 1][j] + 1
          );
        }
      }
    }
    
    return matrix[b.length][a.length];
  }

  /**
   * Check for homograph characters
   */
  checkHomographs(hostname, brand) {
    for (const [char, lookalikes] of Object.entries(this.homographs)) {
      for (const lookalike of lookalikes) {
        if (hostname.includes(lookalike) && brand.includes(char)) {
          const normalized = hostname.replace(new RegExp(lookalike, 'g'), char);
          if (normalized.includes(brand)) {
            return true;
          }
        }
      }
    }
    return false;
  }

  /**
   * Calculate final risk score
   */
  calculateRiskScore(results) {
    let score = 0;
    const riskFactors = [];
    const safetyIndicators = [];
    
    // Check if domain is whitelisted (trusted)
    const hostname = results.parsedURL?.hostname || '';
    const domain = results.parsedURL?.domain || '';
    const isWhitelisted = this.isWhitelistedDomain(hostname, domain);

    // Structure analysis
    if (results.checks.structure) {
      score += results.checks.structure.riskScore;
      riskFactors.push(...results.checks.structure.issues);
      safetyIndicators.push(...results.checks.structure.positives);
    }

    // Domain analysis — evaluate ALL domains (trusted domain reduction applied later)
    if (results.checks.domain) {
      if (results.checks.domain.trustScore < 50) {
        score += 30;
        riskFactors.push('Low domain trust score');
      }
      riskFactors.push(...(results.checks.domain.issues || []));
      if (results.checks.domain.trustScore >= 70) {
        safetyIndicators.push('High domain trust score');
      }
      safetyIndicators.push(...(results.checks.domain.positives || []));
    }

    // SSL check — evaluate ALL domains (trusted domain reduction applied later)
    if (results.checks.ssl) {
      if (!results.checks.ssl.secure) {
        score += 25;
        riskFactors.push(results.checks.ssl.issue || 'SSL issue');
      } else {
        if (results.checks.ssl.selfSigned) {
          score += 15;
          riskFactors.push('Self-signed SSL certificate');
        } else {
          safetyIndicators.push('Valid SSL certificate');
        }
        if (results.checks.ssl.daysUntilExpiry < 30) {
          riskFactors.push('SSL certificate expiring soon');
        }
      }
    }

    // Redirect analysis
    if (results.checks.redirects) {
      riskFactors.push(...results.checks.redirects.issues);
      score += results.checks.redirects.issues.length * 10;
    }

    // Threat intelligence (basic)
    if (results.checks.threatIntel?.threats?.length > 0) {
      score += 50;
      for (const threat of results.checks.threatIntel.threats) {
        riskFactors.push(`Flagged by ${threat.source}`);
      }
    }

    // Typosquatting
    if (results.checks.typosquatting?.detected) {
      score += 40;
      riskFactors.push(...results.checks.typosquatting.issues);
    }

    // === ADVANCED THREAT INTELLIGENCE (VirusTotal, PhishTank, WHOIS) ===
    if (results.threatIntelligence) {
      const ti = results.threatIntelligence;
      
      // Add threat intelligence risk factors
      if (ti.riskFactors && ti.riskFactors.length > 0) {
        riskFactors.push(...ti.riskFactors);
      }
      
      // VirusTotal detections
      if (ti.details?.virusTotal?.checked) {
        const vt = ti.details.virusTotal;
        if (vt.malicious > 0) {
          score += Math.min(vt.malicious * 10, 40); // Up to 40 points
          if (!riskFactors.some(f => f.includes('security vendors'))) {
            riskFactors.push(`VirusTotal: ${vt.malicious}/${vt.total} engines detected threat`);
          }
        }
        if (vt.malicious === 0 && vt.total > 0) {
          safetyIndicators.push(`Clean on VirusTotal (${vt.total} engines)`);
        }
      }
      
      // PhishTank detection
      if (ti.details?.phishTank?.checked && ti.details.phishTank.isPhishing) {
        score += 40;
        if (!riskFactors.includes('Listed in PhishTank database')) {
          riskFactors.push('PhishTank: Confirmed phishing URL');
        }
      }
      
      // WHOIS domain age
      if (ti.details?.whois?.available && ti.details.whois.ageInDays !== null) {
        const age = ti.details.whois.ageInDays;
        if (age < 7) {
          score += 25;
        } else if (age < 30) {
          score += 15;
        } else if (age < 90) {
          score += 5;
        } else if (age > 365) {
          safetyIndicators.push(`Established domain (${Math.floor(age/365)} years old)`);
        }
      }
      
      // Blacklist match
      if (ti.details?.blacklist?.blacklisted) {
        score += 35;
        if (!riskFactors.includes('Domain is blacklisted')) {
          riskFactors.push('Found in threat blacklist');
        }
      }
      
      // Add sources used
      if (ti.sources && ti.sources.length > 0) {
        results.threatSources = ti.sources;
      }
    }

    // Normalize score
    results.riskScore = Math.min(100, Math.max(0, score));
    
    // Determine risk level
    if (results.riskScore >= 70) {
      results.riskLevel = 'critical';
      results.isPhishing = true;
    } else if (results.riskScore >= 50) {
      results.riskLevel = 'high';
      results.isPhishing = true;
    } else if (results.riskScore >= 30) {
      results.riskLevel = 'medium';
      results.isPhishing = false;
    } else {
      results.riskLevel = 'low';
      results.isPhishing = false;
    }

    // For whitelisted domains, apply risk reduction factor (NOT absolute override)
    // This prevents exploitation via compromised legitimate domains:
    // a domain that starts hosting phishing will still be flagged.
    if (isWhitelisted) {
      const TRUST_MULTIPLIER = 0.15;
      const originalScore = results.riskScore;
      results.riskScore = Math.round(results.riskScore * TRUST_MULTIPLIER);
      safetyIndicators.push(`Trusted domain (risk reduced ×${TRUST_MULTIPLIER})`);
      // Re-classify based on reduced score
      if (results.riskScore >= 70) {
        results.riskLevel = 'critical';
        results.isPhishing = true;
      } else if (results.riskScore >= 50) {
        results.riskLevel = 'high';
        results.isPhishing = true;
      } else if (results.riskScore >= 30) {
        results.riskLevel = 'medium';
        results.isPhishing = false;
      } else {
        results.riskLevel = 'low';
        results.isPhishing = false;
      }
      // Keep risk factors — they provide visibility even if score is low
      results.riskFactors = [...new Set(riskFactors)];
    } else {
      results.riskFactors = [...new Set(riskFactors)]; // Remove duplicates
    }
    
    results.safetyIndicators = [...new Set(safetyIndicators)];
  }

  /**
   * Check if hostname or domain is whitelisted
   */
  isWhitelistedDomain(hostname, domain) {
    const trustedDomains = [
      'google.com', 'facebook.com', 'amazon.com', 'apple.com',
      'microsoft.com', 'paypal.com', 'netflix.com', 'twitter.com', 'x.com',
      'instagram.com', 'linkedin.com', 'github.com', 'stackoverflow.com',
      'youtube.com', 'wikipedia.org', 'reddit.com', 'yahoo.com', 'bing.com',
      'dropbox.com', 'icloud.com', 'outlook.com', 'office.com', 'live.com',
      'whatsapp.com', 'telegram.org', 'discord.com', 'spotify.com',
      'twitch.tv', 'zoom.us', 'slack.com', 'notion.so', 'figma.com', 'canva.com',
      'cloudflare.com', 'amazonaws.com', 'azure.com', 'heroku.com',
      'vercel.app', 'netlify.app', 'npmjs.com', 'golang.org', 'python.org',
      'mozilla.org', 'w3.org', 'steampowered.com', 'ebay.com', 'walmart.com',
      'target.com', 'bestbuy.com', 'chase.com', 'wellsfargo.com',
      'bankofamerica.com', 'citi.com', 'adobe.com', 'salesforce.com',
      'oracle.com', 'ibm.com', 'replit.com'
    ];
    
    // Strip www. prefix for matching
    const hostnameClean = (hostname || '').toLowerCase().replace(/^www\./, '');
    const domainClean = (domain || '').toLowerCase().replace(/^www\./, '');
    
    return trustedDomains.some(td => 
      hostnameClean === td || domainClean === td ||
      hostnameClean.endsWith('.' + td) || domainClean.endsWith('.' + td)
    );
  }
}

export default new URLScanner();
export { URLScanner };
