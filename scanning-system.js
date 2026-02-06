/**
 * PhishNet Scanning System
 * Handles scan creation, result display, dashboard updates, and report generation
 */

class ScanningSystem {
  constructor() {
    this.scanHistory = [];
    this.currentScan = null;
    this.loadScanHistory().then(() => {
        // Initialize UI after history loaded
        this.init();
      }).catch((err) => {
        console.error('[ScanningSystem] Failed to load history before init:', err);
        // Fallback to init anyway
        this.init();
      });
  }

  init() {
    // Initialization (scan history already loaded before init)

    console.log('[ScanningSystem] Init called, path:', window.location.pathname);

    // Only initialize homepage scanning on index.html
    if (window.location.pathname.includes('index.html') || window.location.pathname === '/') {
      console.log('[ScanningSystem] Initializing homepage...');
      this.initHomepageScanning();
    }

    // Only initialize dashboard on dashboard.html
    if (window.location.pathname.includes('dashboard.html')) {
      console.log('[ScanningSystem] Initializing dashboard...');
      this.initDashboard();
    }

    // Only initialize reports on reports.html
    if (window.location.pathname.includes('reports.html')) {
      console.log('[ScanningSystem] Initializing reports...');
      this.initReportsPage();
    }
  }

  /**
   * Map server threatLevel to frontend threat labels
   */
  mapThreatLevel(threatLevel) {
    if (threatLevel === 'safe') return 'safe';
    if (threatLevel === 'low' || threatLevel === 'medium') return 'suspicious';
    if (threatLevel === 'high' || threatLevel === 'critical') return 'malicious';
    return 'safe'; // default
  }

  /**
   * Load scan history from localStorage
   */
  async loadScanHistory() {
    try {
      const token = localStorage.getItem('token');
      if (!token) {
        console.log('[ScanningSystem] No token found, loading from localStorage');
        // Load from localStorage for non-logged-in users
        const storedHistory = localStorage.getItem('scanHistory');
        this.scanHistory = storedHistory ? JSON.parse(storedHistory) : [];
        return;
      }

      const response = await fetch(getApiUrlWithParams(window.API_CONFIG.api.endpoints.users.history, { limit: 100 }), {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (response.ok) {
        const data = await response.json();
          if (data.success) {
          // Transform API data to match frontend format
          const serverItems = data.data.history.map(item => {
              const rawThreat = item.threatLevel || item.threat || item.status || (item.isSafe === true ? 'safe' : (item.isSafe === false ? 'malicious' : null));
              const normalizedThreat = rawThreat && (['safe', 'suspicious', 'malicious'].includes(String(rawThreat).toLowerCase()))
                ? String(rawThreat).toLowerCase()
                : this.mapThreatLevel(rawThreat);

              return ({
                id: item._id,
                // Detect email scans robustly: prefer explicit scanType, else check sender/email/value/url for an email address
                type: (function() {
                  const explicit = String(item.scanType || '').toLowerCase();
                  if (explicit && explicit.indexOf('email') !== -1) return 'email';
                  const probe = String(item.senderEmail || item.email || item.value || item.url || '');
                  return probe.indexOf('@') !== -1 ? 'email' : 'url';
                })(),
                value: (function() {
                  const t = String(item.scanType || '').toLowerCase();
                  const probe = String(item.senderEmail || item.email || item.value || item.url || '');
                  if (t.indexOf('email') !== -1 || probe.indexOf('@') !== -1) return (item.senderEmail || item.email || item.value || item.url || '');
                  return (item.url || item.value || '');
                })(),
                threat: normalizedThreat || 'safe',
                threatType: item.threatType,
                confidence: item.confidence,
                timestamp: new Date(item.checkedAt).getTime(),
                date: new Date(item.checkedAt).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' }),
                time: new Date(item.checkedAt).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: true }),
                indicators: item.indicators || [],
                issues: item.issues || [],
                summary: item.summary || '',
                riskLevel: (item.riskLevel || item.risk) ? (typeof (item.riskLevel || item.risk) === 'string' ? item.riskLevel || item.risk : String(item.riskLevel || item.risk)) : null,
                // compute fallback riskLevel from threat/threatLevel if missing
                computedRiskLevel: null,
                domain: item.domain,
                isSafe: item.isSafe,
                details: item.details, // Include details for email scans
                // preserve full server record to allow detailed viewer to access all fields
                raw: item
              });
            });

          // Merge with any local-only entries but prefer server records.
          // Remove local entries that appear to be the same scan (same value within 5s)
          let localStored = [];
          try {
            const stored = localStorage.getItem('scanHistory');
            localStored = stored ? JSON.parse(stored) : [];
          } catch (e) {
            localStored = [];
          }

          const remainingLocal = (localStored || []).filter(local => {
            // Keep only local entries that are not duplicates of server records
            try {
              if (!local || !local.value) return true;
              const localTs = Number(local.timestamp) || 0;
              const duplicate = serverItems.some(srv => {
                const srvTs = Number(srv.timestamp) || 0;
                return String((srv.value||'').trim()) === String((local.value||'').trim()) && Math.abs(srvTs - localTs) < 5000;
              });
              return !duplicate;
            } catch (e) {
              return true;
            }
          });

          // derive readable riskLevel for server items when missing
          const deriveRisk = (rl, thr, rawThreatLevel) => {
            if (rl) return rl;
            const t = (thr || '').toString().toLowerCase();
            if (t === 'safe') return 'Low';
            if (t === 'suspicious') return 'Medium';
            if (t === 'malicious') return 'High';
            const r = (rawThreatLevel || '').toString().toLowerCase();
            if (r === 'low') return 'Low';
            if (r === 'medium') return 'Medium';
            if (r === 'high' || r === 'critical') return 'High';
            return null;
          };

          serverItems.forEach(si => {
            try {
              const rawThr = si.raw && (si.raw.threatLevel || si.raw.threat) ? si.raw.threatLevel || si.raw.threat : null;
              const thrLabel = si.threat || rawThr;
              si.computedRiskLevel = deriveRisk(si.riskLevel || null, thrLabel, rawThr) || (si.riskLevel || null);
              // if riskLevel missing, set riskLevel to computedRiskLevel for downstream code
              if (!si.riskLevel && si.computedRiskLevel) si.riskLevel = si.computedRiskLevel;
            } catch (e) {}
          });

          this.scanHistory = [...serverItems, ...remainingLocal];
          console.log(`[ScanningSystem] Loaded ${this.scanHistory.length} scans from server`);
        } else {
          console.error('[ScanningSystem] Failed to load scan history (API error):', data.message);
          // Fallback to localStorage if server responded but with failure
          const storedHistory = localStorage.getItem('scanHistory');
          this.scanHistory = storedHistory ? JSON.parse(storedHistory) : [];
        }
      } else {
        if (response.status === 401) {
          console.warn('[ScanningSystem] Unauthorized - clearing token and cached scan data');
          localStorage.removeItem('token');
          localStorage.removeItem('scanHistory');
          localStorage.removeItem('selectedScan');
          localStorage.removeItem('selectedScanId');
          if (window.scanManager) window.scanManager.scanHistory = [];
          this.scanHistory = [];
          return;
        }
        console.error('[ScanningSystem] Failed to fetch scan history:', response.status);
        // Fallback to localStorage when fetch fails
        const storedHistory = localStorage.getItem('scanHistory');
        this.scanHistory = storedHistory ? JSON.parse(storedHistory) : [];
      }
    } catch (error) {
      console.error('[ScanningSystem] Error loading scan history:', error);
      // On network or unexpected error, fallback to localStorage to preserve UI state
      const storedHistory = localStorage.getItem('scanHistory');
      this.scanHistory = storedHistory ? JSON.parse(storedHistory) : [];
    }
  }

  /**
   * Ensure every scan has a stable numeric id (for view/delete actions)
   */
  ensureScanIds(list) {
    const base = Date.now();
    return list.map((scan, idx) => {
      if (scan && scan.id) return scan;
      return { ...scan, id: `local-${base + idx}` };
    });
  }

  /**
   * Save scan to localStorage and update all related pages
   */
  async saveScan(scan) {
    // Prevent duplicate save calls for the same scan fired within a short window
    try {
      const fingerprint = `${scan.type}|${(scan.value||'').toString().slice(0,200)}|${scan.threat||scan.status||''}`;
      const now = Date.now();
      if (!this._saveHistory) this._saveHistory = { lastFingerprint: null, lastTs: 0 };
      if (this._saveHistory.lastFingerprint === fingerprint && (now - this._saveHistory.lastTs) < 3000) {
        console.log('[ScanningSystem] Duplicate save detected, skipping duplicate request');
        return scan;
      }
      // mark attempt timestamp immediately to avoid concurrent duplicates
      this._saveHistory.lastFingerprint = fingerprint;
      this._saveHistory.lastTs = now;
    } catch (e) {
      // ignore fingerprinting errors and continue
    }
    const token = localStorage.getItem('token');

    if (token) {
      // Logged-in user: send scan to Auth backend (port 5000) so it's stored under the user's account
      try {
        // Use Auth backend's /api/scan/url or /api/scan/email endpoint to save to MongoDB
        const isEmail = String(scan.type || '').toLowerCase().includes('email');
        const saveEndpoint = isEmail 
          ? (window.API_CONFIG.api.endpoints.history?.saveEmail || '/api/scan/email')
          : (window.API_CONFIG.api.endpoints.history?.saveUrl || '/api/scan/url');
        
        // Build the full URL to the Auth backend (port 5000)
        const endpoint = `${window.API_CONFIG.api.authBaseURL}${saveEndpoint}`;

        // Build an enriched body containing analysis fields so server persists UI classification
        // Normalize frontend threat labels to server-expected enums to avoid validation errors
        let outgoingThreat = scan.status || scan.threat || scan.threatLevel || 'safe';
        outgoingThreat = String(outgoingThreat || '').toLowerCase();
        const threatLevelMap = { suspicious: 'medium', malicious: 'high' };
        if (!['safe', 'low', 'medium', 'high', 'critical'].includes(outgoingThreat)) {
          outgoingThreat = threatLevelMap[outgoingThreat] || 'low';
        }

        const commonAnalysis = {
          isSafe: scan.status ? (scan.status === 'safe') : (scan.isSafe === true),
          threatLevel: outgoingThreat,
          threatType: scan.threatType || scan.threat || null,
          confidence: typeof scan.confidence !== 'undefined' ? scan.confidence : (scan.riskPercent || null),
          indicators: scan.indicators || [],
          issues: scan.issues || [],
          summary: scan.summary || scan.details || '',
          details: scan.details || null,
          scanType: scan.type || (scan.value && String(scan.value).includes('@') ? 'email' : 'url'),
          domain: scan.domain || null
        };

        // Extract sender email from email content if not provided
        const extractSenderEmail = (text) => {
          if (!text) return '';
          const emailRegex = /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i;
          const match = String(text).match(emailRegex);
          return match ? match[0] : '';
        };

        const body = (String(scan.type || '').toLowerCase().includes('email'))
          ? Object.assign({}, commonAnalysis, { 
              senderEmail: scan.senderEmail || extractSenderEmail(scan.value) || 'unknown@local', 
              emailContent: scan.value || '', 
              subject: scan.subject || '' 
            })
          : Object.assign({}, commonAnalysis, { url: scan.value });

        const response = await fetch(endpoint, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`,
          },
          body: JSON.stringify(body)
        });

        if (!response.ok) {
          console.warn('[ScanningSystem] Server returned error when saving scan, falling back to local save');
          this.saveScanToLocal(scan);
        } else {
          const data = await response.json();
          if (!data.success) {
            console.warn('[ScanningSystem] API responded with failure:', data.message);
            this.saveScanToLocal(scan);
          } else {
            // Reload server history to reflect user's saved scan
            await this.loadScanHistory();
          }
        }
      } catch (err) {
        console.error('[ScanningSystem] Error while saving scan to server, saving locally instead', err);
        this.saveScanToLocal(scan);
      }
    } else {
      // Non-logged-in user: save to localStorage
      console.log('[ScanningSystem] Saving scan to localStorage for non-logged-in user');
      this.saveScanToLocal(scan);
    }

    // Update dashboard if it's open
    if (window.location.pathname.includes('dashboard.html')) {
      this.updateDashboardTable();
      // Also refresh dashboard data (stats, alerts, chart)
      if (typeof window.refreshDashboardData === 'function') {
        window.refreshDashboardData();
      }
    }

    // Update reports page if it's open
    if (window.location.pathname.includes('reports.html')) {
      // Trigger reports page refresh if ReportsManager exists
      if (window.reportsManager) {
        window.reportsManager.loadScanHistory();
        window.reportsManager.renderReports();
      }
    }

    console.log('[ScanningSystem] Scan saved successfully');
    return scan;
  }

  saveScanToLocal(scan) {
    // Add timestamp and string ID
    scan.timestamp = new Date().getTime();
    scan.id = `local-${scan.timestamp}`;
    scan.date = new Date().toLocaleDateString('en-US', { 
      month: 'short', 
      day: 'numeric', 
      year: 'numeric' 
    });
    scan.time = new Date().toLocaleTimeString('en-US', { 
      hour: '2-digit', 
      minute: '2-digit' 
    });

    // Map 'status' to 'threat' for consistency
    if (scan.status && !scan.threat) {
      scan.threat = scan.status;
    }

    // Add to beginning of array (most recent first)
    // Prevent obvious duplicates: if last saved has same value & threat within 2s, skip
    const last = this.scanHistory[0];
    if (last && last.value === scan.value) {
      const lastTime = Number(last.timestamp) || 0;
      if (Math.abs(lastTime - scan.timestamp) < 2000 && (String(last.threat || last.status || '') === String(scan.threat || scan.status || ''))) {
        console.log('[ScanningSystem] Skipping duplicate local save');
      } else {
        this.scanHistory.unshift(scan);
      }
    } else {
      this.scanHistory.unshift(scan);
    }

    // Save to localStorage
    localStorage.setItem('scanHistory', JSON.stringify(this.scanHistory));

    // Update dashboard if it's open
    if (window.location.pathname.includes('dashboard.html')) {
      this.updateDashboardTable();
    }

    // Update reports page if it's open
    if (window.location.pathname.includes('reports.html')) {
      // Trigger reports page refresh if ReportsManager exists
      if (window.reportsManager) {
        window.reportsManager.loadScanHistory();
        window.reportsManager.renderReports();
      }
    }

    // Synchronize with ScanManager instance (if present) so any UI using it refreshes
    try {
      if (window.scanManagerInstance && Array.isArray(this.scanHistory)) {
        window.scanManagerInstance.scanHistory = this.scanHistory;
        if (typeof window.scanManagerInstance.displayScanHistory === 'function') {
          window.scanManagerInstance.displayScanHistory();
        }
      }
    } catch (err) {
      console.warn('[ScanningSystem] sync to ScanManager failed', err);
    }
  }

  /**
   * Initialize homepage scanning functionality
   */
  initHomepageScanning() {
    console.log('Initializing homepage scanning...');
    console.log('Current path:', window.location.pathname);
    
    // URL form submission
    const urlForm = document.querySelector('#panel-url form');
    console.log('URL form found:', !!urlForm);
    if (urlForm) {
      urlForm.addEventListener('submit', (e) => this.handleUrlScan(e));
    }

    // Email form submission
    const emailForm = document.querySelector('#panel-email form');
    console.log('Email form found:', !!emailForm);
    if (emailForm) {
      emailForm.addEventListener('submit', (e) => this.handleEmailScan(e));
    }

    // Close buttons are now handled in displayResult() for dynamic results

    // View report buttons handled via report navigation
    console.log('Homepage scanning initialized ✓');
  }

  /**
   * Call backend Safe Browsing endpoint
   */
  async scanUrlViaBackend(url) {
    console.log('[scanUrlViaBackend] Sending scan request', { url, urlType: typeof url, urlLength: url?.length });
    const token = localStorage.getItem('token');
    const response = await fetch(getApiUrl(window.API_CONFIG.api.endpoints.scan.url), {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(token ? { Authorization: `Bearer ${token}` } : {})
      },
      body: JSON.stringify({ url })
    });

    const data = await response.json().catch(() => ({}));
    console.log('[scanUrlViaBackend] Response received', { status: response.status, ok: response.ok, data });
    if (!response.ok || data.success === false) {
      console.error('[scanUrlViaBackend] Error details:', data);
      throw new Error(data?.message || 'Failed to scan URL');
    }

    return data;
  }

  /**
   * Normalize Safe Browsing response to UI-friendly format
   */
  normalizeSafeBrowsingResult(url, apiResult, elapsedMs) {
    // Handle new Advanced URL Scanner response format
    const data = apiResult?.data || apiResult;
    
    // Check for new format (isPhishing, riskLevel, riskScore)
    if (data?.isPhishing !== undefined || data?.riskLevel !== undefined) {
      const isPhishing = data.isPhishing === true;
      const riskLevel = (data.riskLevel || 'low').toLowerCase();
      const riskScore = data.riskScore || 0;
      const riskFactors = data.riskFactors || [];
      const safetyIndicators = data.safetyIndicators || [];
      
      // Determine status based on risk level
      let status = 'safe';
      if (riskLevel === 'critical' || riskLevel === 'high' || isPhishing) {
        status = 'malicious';
      } else if (riskLevel === 'medium') {
        status = 'suspicious';
      }
      
      const threatType = isPhishing ? 'phishing' : status === 'malicious' ? 'malware' : status === 'suspicious' ? 'suspicious' : 'safe';
      const displayRiskLevel = status === 'malicious' ? 'High' : status === 'suspicious' ? 'Medium' : 'Low';
      const riskPercent = Math.round(riskScore);
      
      // Build summary
      let summary = '';
      if (status === 'malicious') {
        summary = `WARNING: This URL has been identified as a security threat! Risk Score: ${riskPercent}%. `;
        if (riskFactors.length > 0) {
          summary += `Detected issues: ${riskFactors.slice(0, 3).join(', ')}.`;
        }
        summary += ' Do NOT enter any personal information or credentials on this site.';
      } else if (status === 'suspicious') {
        summary = `CAUTION: This URL shows some warning signs. Risk Score: ${riskPercent}%. Exercise caution before proceeding.`;
      } else {
        summary = 'This URL appears to be safe and legitimate. No security threats were detected.';
      }
      
      // Build issues list - for SAFE status, only show safety indicators, not risk factors
      let issues;
      if (status === 'safe') {
        // For safe URLs, show safety indicators as positive confirmations
        issues = safetyIndicators.length > 0 
          ? safetyIndicators.map(s => `✓ ${s}`)
          : ['✓ No security threats detected', '✓ URL appears legitimate'];
      } else {
        // For suspicious/malicious, show risk factors as warnings
        issues = riskFactors.length > 0 
          ? riskFactors.map(f => `⚠ ${f}`)
          : ['⚠ Potential security concern detected'];
      }
      
      // Build indicators - same logic
      let indicators;
      if (status === 'safe') {
        indicators = safetyIndicators.length > 0 
          ? safetyIndicators 
          : ['Security analysis completed - No threats identified'];
      } else {
        indicators = riskFactors.length > 0 
          ? riskFactors 
          : ['Potential security concern detected'];
      }
      
      return {
        status,
        threat: status,
        threatType,
        riskLevel: displayRiskLevel,
        riskPercent,
        issues,
        indicators,
        summary,
        confidence: riskPercent,
        scanTime: data.scanTime ? (data.scanTime / 1000).toFixed(2) : ((elapsedMs || 0) / 1000).toFixed(2),
        domain: this.extractDomainSafe(url),
        rawThreats: riskFactors,
        isSafe: !isPhishing && status === 'safe',
        urlAnalysis: data.urlAnalysis,
        domainAnalysis: data.domainAnalysis,
        mlAnalysis: data.mlAnalysis
      };
    }
    
    // Fallback: Handle old Safe Browsing API format
    const threatList = Array.isArray(apiResult?.threats) ? apiResult.threats : [];
    const hasThreats = threatList.length > 0;
    const threatTypes = threatList.map((t) => (t.type || t.threatType || '').toUpperCase());
    const hasMalware = threatTypes.includes('MALWARE');
    const hasPhishing = threatTypes.includes('SOCIAL_ENGINEERING') || threatTypes.includes('PHISHING');
    const hasUnwanted = threatTypes.includes('UNWANTED_SOFTWARE');
    const status = hasThreats ? ((hasMalware || hasPhishing) ? 'malicious' : 'suspicious') : 'safe';
    const threatType = hasPhishing ? 'phishing' : hasMalware ? 'malware' : hasUnwanted ? 'unsafe' : 'safe';
    const riskLevel = status === 'malicious' ? 'High' : status === 'suspicious' ? 'Medium' : 'Low';
    const riskPercent = status === 'malicious' ? 95 : status === 'suspicious' ? 55 : 5;
    
      // Use summary from API if available, otherwise generate it
      const summary = apiResult?.summary || (status === 'safe'
      ? 'Our comprehensive security analysis has completed a thorough examination of this URL and found no indicators of malicious activity, phishing attempts, or unwanted software. The URL has passed all security checks including domain reputation analysis, SSL certificate validation, and behavioral pattern matching. This resource appears legitimate and safe for user interaction.'
      : status === 'malicious'
        ? `This URL has been identified as a significant security threat and presents serious risks to users. Our advanced threat detection algorithms have flagged this resource for ${hasMalware ? 'malware distribution' : ''}${hasMalware && hasPhishing ? ' and ' : ''}${hasPhishing ? 'phishing attempts designed to steal credentials' : ''}. We strongly recommend avoiding this URL entirely and blocking access through your security systems. Do not enter personal information, credentials, or download any files from this source.`
          : `This URL exhibits suspicious characteristics that warrant extreme caution. Our security analysis has detected ${hasUnwanted ? 'unwanted software patterns' : 'anomalous behavior'} commonly associated with potentially harmful activities. While not definitively malicious, this resource shows signs of deceptive practices, unusual redirect patterns, or attempts to deliver unwanted content. We recommend thorough verification before interacting with this URL.`);
    
      // Use issues from API if available, otherwise generate them
      const issues = apiResult?.issues || (hasThreats
      ? threatList.map((t) => `Flagged for ${String(t.type || t.threatType || 'THREAT').replace(/_/g, ' ')}`)
        : ['No security threats detected']);
      
      // Use indicators from API if available, otherwise generate them
      const indicators = apiResult?.indicators || (hasThreats
      ? threatList.map((t) => `${String(t.platform || t.platformType || 'ANY_PLATFORM').replace(/_/g, ' ')} · ${String(t.type || t.threatType || 'THREAT').replace(/_/g, ' ')}`)
        : ['Security analysis completed - No threats identified']);

    return {
      status,
      threat: status,
      threatType,
      riskLevel,
      riskPercent,
      issues,
      indicators,
      summary,
        confidence: apiResult?.confidence || (status === 'safe' ? 90 : 98),
      scanTime: ((elapsedMs || 0) / 1000).toFixed(2),
      domain: this.extractDomainSafe(url),
      rawThreats: threatList,
        isSafe: apiResult?.isSafe !== undefined ? apiResult.isSafe : (status === 'safe'),
    };
  }

  extractDomainSafe(url) {
    try {
      return new URL(url).hostname;
    } catch (err) {
      return url;
    }
  }

  /**
   * Handle URL scan
   */
  async handleUrlScan(e) {
    e.preventDefault();
    const form = e.target instanceof HTMLFormElement ? e.target : e.currentTarget;
    const submitBtn = form ? form.querySelector('button[type="submit"]') : null;
    const originalLabel = submitBtn ? submitBtn.textContent : '';
    if (submitBtn) {
      submitBtn.disabled = true;
      submitBtn.textContent = 'Scanning...';
      submitBtn.classList.add('loading');
    }
    console.log('[handleUrlScan] Scan started');

    const urlInput = document.getElementById('url-input');
    const url = urlInput ? urlInput.value.trim() : '';
    if (!url) {
      this.showNotification('Please enter a URL', 'error');
      if (submitBtn) {
        submitBtn.disabled = false;
        submitBtn.textContent = originalLabel || 'Scan URL';
        submitBtn.classList.remove('loading');
      }
      return;
    }

    console.log('[handleUrlScan] Scanning URL:', url);

    // Show loading state
    const resultsSection = document.getElementById('results-section');
    if (resultsSection) resultsSection.style.display = 'block';

    try {
      const startTime = performance.now();
      const apiResult = await this.scanUrlViaBackend(url);
      const normalized = this.normalizeSafeBrowsingResult(url, apiResult, performance.now() - startTime);

      console.log('[handleUrlScan] Normalized result', normalized);

      await this.saveScan({
        type: 'url',
        value: url,
        ...normalized
      });

      this.displayUrlResult(normalized);

      // Scroll to results
      if (resultsSection) {
        resultsSection.scrollIntoView({ behavior: 'smooth' });
      }
    } catch (error) {
      console.error('[handleUrlScan] Failed:', error);
      this.showNotification(error?.message || 'Failed to scan URL', 'error');
    } finally {
      if (submitBtn) {
        submitBtn.disabled = false;
        submitBtn.textContent = originalLabel || 'Scan URL';
        submitBtn.classList.remove('loading');
      }
    }
  }

  /**
   * Handle Email scan
   */
  async handleEmailScan(e) {
    e.preventDefault();
    const form = e.target instanceof HTMLFormElement ? e.target : e.currentTarget;
    const submitBtn = form ? form.querySelector('button[type="submit"]') : null;
    const originalLabel = submitBtn ? submitBtn.textContent : '';
    if (submitBtn) {
      submitBtn.disabled = true;
      submitBtn.textContent = 'Scanning...';
      submitBtn.classList.add('loading');
    }
    console.log('[handleEmailScan] Scan started');

    const email = document.getElementById('email-input').value.trim();
    if (!email) {
      this.showNotification('Please enter email content', 'error');
      if (submitBtn) {
        submitBtn.disabled = false;
        submitBtn.textContent = originalLabel || 'Scan Email';
        submitBtn.classList.remove('loading');
      }
      return;
    }

    console.log('[handleEmailScan] Scanning email content');

    // Show loading state
    const resultsSection = document.getElementById('results-section');
    if (resultsSection) resultsSection.style.display = 'block';

    const startTime = performance.now();
    let scanResult;
    
    try {
      // Try calling the real backend API
      scanResult = await this.scanEmailViaBackend(email);
      console.log('[handleEmailScan] Backend scan result:', scanResult);
    } catch (error) {
      console.warn('[handleEmailScan] Backend unavailable, using fallback:', error.message);
      // Fallback to mock scan if backend is unavailable
      scanResult = this.generateEmailScanResult(email);
    }
    
    const endTime = performance.now();
    scanResult.scanTime = ((endTime - startTime) / 1000).toFixed(2);

    // Save to history (refreshes from server for logged-in users)
    await this.saveScan({
      type: 'email',
      value: email,
      ...scanResult
    });
    
    // Display result
    console.log('[handleEmailScan] Displaying result:', scanResult);
    this.displayEmailResult(scanResult);

    // Scroll to results
    if (resultsSection) resultsSection.scrollIntoView({ behavior: 'smooth' });
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.textContent = originalLabel || 'Scan Email';
      submitBtn.classList.remove('loading');
    }
  }

  /**
   * Call backend email scan endpoint (PhishingDistilBERT model)
   */
  async scanEmailViaBackend(emailContent) {
    const API_BASE = window.CONFIG?.API_BASE_URL || 'http://localhost:3000';
    
    const response = await fetch(`${API_BASE}/api/scan/email`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ emailContent })
    });
    
    if (!response.ok) {
      throw new Error(`Backend responded with ${response.status}`);
    }
    
    const responseData = await response.json();
    console.log('[scanEmailViaBackend] API response:', responseData);
    
    // Extract data from response (API wraps in {success, data})
    const data = responseData.data || responseData;
    
    // Convert backend response to UI format
    const isPhishing = data.classification === 'phishing';
    const confidence = (data.confidence || 0.5) * 100;
    const status = isPhishing ? (confidence > 80 ? 'malicious' : 'suspicious') : 'safe';
    
    return {
      status,
      threat: status,
      riskLevel: status === 'safe' ? 'Low' : status === 'suspicious' ? 'Medium' : 'High',
      riskPercent: isPhishing ? Math.round(confidence) : Math.round(100 - confidence),
      issues: isPhishing 
        ? [`Phishing detected with ${confidence.toFixed(1)}% confidence`, ...(data.indicators || [])]
        : ['No phishing indicators detected', 'Email appears safe'],
      indicators: data.indicators || (isPhishing 
        ? ['⚠ Phishing patterns detected', '⚠ Suspicious content'] 
        : ['✓ No phishing patterns', '✓ Safe content']),
      summary: isPhishing
        ? `WARNING: This email has been identified as a potential phishing attempt with ${confidence.toFixed(1)}% confidence. ${(data.indicators || []).join('. ')}. Exercise extreme caution - do not click links or download attachments.`
        : `This email appears to be legitimate. Our PhishingDistilBERT model analysis found no phishing indicators (${(100 - confidence).toFixed(1)}% safe confidence). The content does not match known phishing patterns.`,
      confidence: confidence,
      isSafe: !isPhishing,
      model: data.model || 'PhishingDistilBERT'
    };
  }

  /**
   * Generate mock URL scan result
   */
  generateUrlScanResult(url) {
    const threats = [
      {
        status: 'safe',
        riskLevel: 'Low',
        riskPercent: 5,
        issues: [
          'Valid SSL certificate detected',
          'Domain age: 5+ years',
          'No known phishing indicators'
        ],
        indicators: [
          '✓ Valid SSL Certificate',
          '✓ Legitimate Domain Owner',
          '✓ No Malware Detected',
          '✓ Safe Redirect Pattern'
        ],
        summary: 'This URL appears to be safe. It has a valid SSL certificate, legitimate domain ownership, and no known phishing indicators. You can safely visit this website.',
        confidence: 98
      },
      {
        status: 'suspicious',
        riskLevel: 'Medium',
        riskPercent: 55,
        issues: [
          'Recently registered domain',
          'Domain name similar to popular service',
          'Unusual redirect pattern detected'
        ],
        indicators: [
          '⚠ Recently Registered Domain',
          '⚠ Similar Domain Name Pattern',
          '⚠ Multiple Redirects Detected',
          '✓ Valid Certificate'
        ],
        summary: 'This URL shows some suspicious characteristics. While not confirmed malicious, exercise caution. The domain was recently registered and uses a naming pattern similar to legitimate services. Consider verifying the website\'s authenticity before entering sensitive information.',
        confidence: 82
      },
      {
        status: 'malicious',
        riskLevel: 'High',
        riskPercent: 95,
        issues: [
          'Known phishing domain',
          'Domain spoofing popular service',
          'Malware detected on site',
          'Credential harvesting indicators'
        ],
        indicators: [
          '✕ Malicious URL Database Match',
          '✕ Domain Spoofing Detected',
          '✕ Keylogger/Malware Signatures',
          '✕ Credential Harvesting Form'
        ],
        summary: 'WARNING: This URL has been identified as malicious. It matches known phishing sites and contains malware signatures. This is a confirmed threat attempting to steal credentials or distribute malware. DO NOT VISIT or enter any personal information.',
        confidence: 99
      }
    ];

    return threats[Math.floor(Math.random() * threats.length)];
  }

  /**
   * Generate Email scan result using heuristic detection (consistent results)
   */
  generateEmailScanResult(emailContent) {
    // Heuristic-based detection for consistent results
    const text = emailContent.toLowerCase();
    let phishingScore = 0;
    let issues = [];
    let indicators = [];
    let isVerifiedLegitimate = false;

    // Check for email headers and authentication results
    const hasHeaders = /^(from:|received:|return-path:|reply-to:|authentication-results:)/im.test(emailContent);
    
    if (hasHeaders) {
      // Parse authentication results
      const spfPass = /spf=pass/i.test(emailContent);
      const dkimPass = /dkim=pass/i.test(emailContent);
      const dmarcPass = /dmarc=pass/i.test(emailContent);
      
      // Extract sender domain
      const fromMatch = emailContent.match(/from:.*?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/i);
      const senderDomain = fromMatch ? fromMatch[1].toLowerCase() : null;
      
      // Known legitimate domains
      const legitimateDomains = {
        netflix: ['netflix.com', 'mailer.netflix.com'],
        amazon: ['amazon.com', 'amazonses.com'],
        paypal: ['paypal.com'],
        microsoft: ['microsoft.com', 'microsoftonline.com', 'outlook.com'],
        apple: ['apple.com', 'icloud.com'],
        google: ['google.com', 'gmail.com']
      };
      
      // Check if from a verified legitimate domain
      if (senderDomain) {
        for (const [brand, domains] of Object.entries(legitimateDomains)) {
          if (domains.some(d => senderDomain.includes(d))) {
            isVerifiedLegitimate = true;
            indicators.push(`✓ Verified ${brand.charAt(0).toUpperCase() + brand.slice(1)} Domain`);
            phishingScore -= 0.3;
            break;
          }
        }
      }
      
      // Authentication bonuses
      if (spfPass) {
        phishingScore -= 0.15;
        indicators.push('✓ SPF Passed');
      }
      if (dkimPass) {
        phishingScore -= 0.15;
        indicators.push('✓ DKIM Passed');
      }
      if (dmarcPass) {
        phishingScore -= 0.15;
        indicators.push('✓ DMARC Passed');
      }
      
      // Extra bonus if ALL authentication passed AND from verified domain
      if (spfPass && dkimPass && dmarcPass && isVerifiedLegitimate) {
        phishingScore -= 0.2;
        indicators.push('✓ Fully Authenticated');
      }
    }

    // Content penalty multiplier - reduced for verified legitimate emails
    const penaltyMultiplier = isVerifiedLegitimate ? 0.2 : 1.0;

    // Check for urgency keywords (reduced weight for legitimate sources)
    if (/urgent|immediately|asap|click now|verify now|act now|expire|suspended|locked|compromised/i.test(text)) {
      phishingScore += 0.2 * penaltyMultiplier;
      if (!isVerifiedLegitimate) {
        issues.push('Urgent language used to pressure action');
        indicators.push('⚠ Urgency Language Patterns');
      }
    }

    // Check for financial keywords (some are normal in legitimate account emails)
    if (/payment|credit card|bank account|gift card|winner|prize/i.test(text)) {
      phishingScore += 0.2 * penaltyMultiplier;
      if (!isVerifiedLegitimate) {
        issues.push('Financial keywords detected');
        indicators.push('⚠ Financial Keywords Found');
      }
    }
    
    // Password/verify are COMMON in legitimate account notification emails
    if (/password|verify|identity/i.test(text) && !isVerifiedLegitimate) {
      phishingScore += 0.15;
      issues.push('Credential keywords detected');
      indicators.push('⚠ Credential Keywords');
    }

    // Check for suspicious URLs (only if not from verified source)
    if (!isVerifiedLegitimate && /https?:\/\/[^\s]+/i.test(text)) {
      // Check for suspicious URL patterns
      if (/secure[.-]|verify[.-]|confirm[.-]|update[.-]|\.xyz|\.info|\.top|\.click/i.test(text)) {
        phishingScore += 0.2;
        issues.push('Suspicious URL patterns detected');
        indicators.push('⚠ Suspicious Links Detected');
      }
    }

    // Check for impersonal greetings (less relevant for verified emails)
    if (/dear customer|dear user|dear friend|valued customer|account holder/i.test(text) && !isVerifiedLegitimate) {
      phishingScore += 0.1;
      issues.push('Generic greeting detected');
      indicators.push('⚠ Generic Greeting');
    }

    // Check for pressure tactics
    if (/do not ignore|immediate attention|time sensitive|will be suspended|lose access|act now or/i.test(text)) {
      phishingScore += 0.15 * penaltyMultiplier;
      if (!isVerifiedLegitimate) {
        issues.push('Pressure tactics to force quick action');
        indicators.push('⚠ Pressure Tactics');
      }
    }

    // Ensure score stays in valid range
    phishingScore = Math.max(0, Math.min(1, phishingScore));

    // Determine status based on score
    let status, riskLevel, riskPercent, summary;
    
    if (phishingScore >= 0.5) {
      status = 'malicious';
      riskLevel = 'High';
      riskPercent = Math.round(phishingScore * 100);
      indicators.unshift('✕ High Phishing Risk');
      summary = `ALERT: This email shows strong phishing indicators (${riskPercent}% risk). ${issues.join('. ')}. Do NOT click links or provide personal information.`;
    } else if (phishingScore >= 0.25) {
      status = 'suspicious';
      riskLevel = 'Medium';
      riskPercent = Math.round(phishingScore * 100);
      indicators.unshift('⚠ Suspicious Content');
      summary = `This email shows warning signs (${riskPercent}% risk). ${issues.join('. ')}. Exercise caution before taking any action.`;
    } else {
      status = 'safe';
      riskLevel = 'Low';
      riskPercent = Math.round(phishingScore * 100);
      if (issues.length === 0) issues = ['No phishing indicators detected'];
      if (!indicators.some(i => i.startsWith('✓'))) {
        indicators.unshift('✓ No Phishing Patterns');
      }
      summary = isVerifiedLegitimate 
        ? 'This email is from a verified legitimate sender with proper authentication. Safe to interact with.'
        : 'This email appears legitimate. No significant phishing indicators were detected.';
    }

    return {
      status,
      riskLevel,
      riskPercent,
      issues,
      indicators,
      summary,
      confidence: Math.round((status === 'safe' ? (1 - phishingScore) : phishingScore) * 100),
      isSafe: status === 'safe',
      isVerifiedLegitimate
    };
  }

  /**
   * Create fresh result HTML with correct status class
   * This creates a brand new DOM element, never reuses old ones
   */
  createResultHTML(result, resultType) {
    const threat = result.status || 'safe';
    const statusClass = `status-${threat}`;
    
    const labels = { safe: 'Safe', suspicious: 'Suspicious', malicious: 'Malicious' };
    const riskColors = {
      Low: 'low',
      Medium: 'medium',
      High: 'high',
      Critical: 'critical'
    };

    const statusLabel = labels[threat] || 'Unknown';
    const riskClass = riskColors[result.riskLevel] || 'low';

    return `
      <div class="results-card ${statusClass}">
        <button class="close-results-btn" title="Close results">
          <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <line x1="18" y1="6" x2="6" y2="18"></line>
            <line x1="6" y1="6" x2="18" y2="18"></line>
          </svg>
        </button>
        
        <div class="results-header">
          <div class="status-indicator ${statusClass}">
            <svg class="status-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
              <polyline points="22 4 12 14.01 9 11.01"></polyline>
            </svg>
          </div>
          <div class="results-header-text">
            <h3 class="status-label">${statusLabel}</h3>
            <p class="status-subtext">${this.getStatusDescription(threat, resultType)}</p>
          </div>
        </div>

        <div class="results-body">
          <div class="risk-meter">
            <div class="risk-label">
              <span>Risk Level:</span>
              <span class="risk-value ${riskClass}">${result.riskLevel || 'Unknown'}</span>
            </div>
          </div>

          <div class="issues-section">
            <h4>Detected Issues:</h4>
            <ul class="issues-list">
              ${(result.issues || []).map(issue => `<li>${issue}</li>`).join('')}
            </ul>
          </div>

          <div class="analysis-box">
            <h4>Analysis Summary:</h4>
            <p class="analysis-summary">${result.summary || 'No additional information available.'}</p>
          </div>

          <div class="results-meta">
            <span class="scan-time">Scan completed in ${result.scanTime || 1}s</span>
          </div>
        </div>
      </div>
    `;
  }

  /**
   * Get status description based on threat level and type
   */
  getStatusDescription(threat, resultType) {
    const isUrl = resultType === 'url';
    const descriptions = {
      safe: isUrl
        ? 'This URL appears to be safe and legitimate.'
        : 'This email appears to be legitimate and safe.',
      suspicious: isUrl
        ? 'This URL shows some warning signs. Exercise caution.'
        : 'This email shows warning signs. Be cautious.',
      malicious: isUrl
        ? 'This URL is confirmed malicious. Do not visit.'
        : 'This email is confirmed malicious. Delete it.'
    };
    return descriptions[threat] || 'Unknown status';
  }

  /**
   * Display scan result - Renders fresh DOM with correct status class
   */
  displayResult(result, resultType) {
    // Remove any previous result
    const container = document.getElementById('scan-result-container');
    if (container) {
      container.innerHTML = '';
    }

    // Create fresh HTML with status class applied at creation
    const html = this.createResultHTML(result, resultType);
    if (container) {
      container.innerHTML = html;
    }

    // Attach close button handler
    const closeBtn = container?.querySelector('.close-results-btn');
    if (closeBtn) {
      closeBtn.addEventListener('click', (e) => {
        e.preventDefault();
        this.hideResults();
      });
    }

    // Show results section
    const resultsSection = document.getElementById('results-section');
    if (resultsSection) {
      resultsSection.style.display = 'block';
    }
  }

  /**
   * Display URL scan result
   */
  displayUrlResult(result) {
    console.log('Displaying URL result:', result);
    this.displayResult(result, 'url');
  }

  /**
   * Display Email scan result
   */
  displayEmailResult(result) {
    console.log('Displaying Email result:', result);
    this.displayResult(result, 'email');
  }

  /**
   * Hide results section
   */
  hideResults() {
    const resultsSection = document.getElementById('results-section');
    const container = document.getElementById('scan-result-container');
    if (resultsSection) resultsSection.style.display = 'none';
    if (container) container.innerHTML = '';
  }

  /**
   * Navigate to report page
   */
  navigateToReport() {
    window.location.href = 'reports.html';
  }

  /**
   * Initialize dashboard
   */
  initDashboard() {
    this.updateDashboardTable();
  }

  /**
   * Update dashboard recent scans table
   */
  updateDashboardTable() {
    const tbody = document.querySelector("#scan-results-table tbody");
    if (!tbody) return;

    if (this.scanHistory.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; padding: 30px;">No scan results yet.</td></tr>';
      return;
    }

    // Ensure IDs exist before rendering actions (string ids)
    this.scanHistory = this.ensureScanIds(this.scanHistory);
    localStorage.setItem('scanHistory', JSON.stringify(this.scanHistory));

    tbody.innerHTML = '';

    this.scanHistory.forEach((scan) => {
      const tr = document.createElement('tr');

      // Determine result class based on threat level
      const threatVal = (scan.threat || scan.status || 'safe').toString().toLowerCase();
      let resultClass = '';
      if (threatVal === 'safe') {
        resultClass = 'result-safe';
      } else if (threatVal === 'suspicious') {
        resultClass = 'result-suspicious';
      } else if (threatVal === 'malicious') {
        resultClass = 'result-malicious';
      }

      const viewBtn = document.createElement('button');
      viewBtn.className = 'action-btn view-btn';
      viewBtn.dataset.action = 'view';
      viewBtn.dataset.id = String(scan.id);
      viewBtn.title = 'View detailed report';
      viewBtn.textContent = 'View';

      const deleteBtn = document.createElement('button');
      deleteBtn.className = 'action-btn delete-btn';
      deleteBtn.dataset.action = 'delete';
      deleteBtn.dataset.id = String(scan.id);
      deleteBtn.title = 'Delete this result';
      deleteBtn.textContent = 'Delete';

      const extractEmail = (text) => { try { const m = String(text||'').match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i); return m ? m[0] : ''; } catch(e){return '';} };
      const PLACEHOLDER_SENDER = 'Undefined User';
      const displayTarget = String(scan.type || '').toLowerCase().includes('email') ? ((scan.senderEmail || extractEmail(scan.value) || PLACEHOLDER_SENDER)) : (scan.value || scan.url || '');

      tr.innerHTML = `
        <td title="${this.escapeHtml(displayTarget)}">${this.escapeHtml(displayTarget)}</td>
        <td>${scan.type === 'url' ? 'URL' : 'EMAIL'}</td>
        <td class="${resultClass}">${(scan.threat || scan.status || 'safe').toString().charAt(0).toUpperCase() + (scan.threat || scan.status || 'safe').toString().slice(1)}</td>
        <td>${(()=>{const c=Number(scan.confidence);return Number.isFinite(c)?(c<=1?Math.round(c*100):Math.round(c))+'%':'N/A';})()}</td>
        <td>${scan.date} ${scan.time}</td>
        <td class="actions-cell"></td>
      `;

      const actionsCell = tr.querySelector('.actions-cell');
      actionsCell.appendChild(viewBtn);
      actionsCell.appendChild(deleteBtn);

      tbody.appendChild(tr);
    });

    if (!this._dashboardActionsBound) {
      tbody.addEventListener('click', (e) => this.handleDashboardAction(e));
      this._dashboardActionsBound = true;
    }
  }

  async handleDashboardAction(event) {
    const target = event.target;
    if (!(target instanceof HTMLElement)) return;
    if (!target.matches('button[data-action]')) return;
    const action = target.dataset.action;
    const id = target.dataset.id;
    if (!id) return;

    if (action === 'view') {
      this.viewScanReport(id);
    } else if (action === 'delete') {
      await this.deleteScanById(id);
    }
  }

  /**
   * Delete scan from dashboard
   */
  async deleteScanFromDashboard(index) {
    // Deprecated: keep for compatibility, redirect to id-based delete
    const scan = this.scanHistory[index];
    if (scan) {
      await this.deleteScanById(scan.id);
    }
  }

  async deleteScanById(id) {
    const scan = this.scanHistory.find(s => String(s.id) === String(id));
    if (!scan) return;
    const label = String(scan.type || '').toLowerCase().includes('email') ? (scan.senderEmail || (function(t){ try{ const m=String(t).match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i); return m?m[0]:'';}catch(e){return '';}})(scan.value) || '') : (scan.value || scan.url || '');
    const confirmed = await this.confirmDeletion(label);
    if (!confirmed) return;
    const token = localStorage.getItem('token');

    if (token) {
      // Try to delete on server for logged-in users
      try {
        const deleteUrl = getApiUrl(`/api/scan/${id}`);
        const response = await fetch(deleteUrl, {
          method: 'DELETE',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`,
          }
        });

        if (response.ok) {
          const data = await response.json();
          if (data.success) {
            await this.loadScanHistory();
            this.updateDashboardTable();
            const storedSelected = localStorage.getItem('selectedScanId');
            if (storedSelected && String(storedSelected) === String(id)) {
              localStorage.removeItem('selectedScanId');
              localStorage.removeItem('selectedScan');
            }
            this.showNotification('Report deleted', 'info');
            return;
          }
        }
        console.warn('[ScanningSystem] Server failed to delete scan, falling back to local remove');
      } catch (err) {
        console.error('[ScanningSystem] Error deleting scan on server, falling back to local remove', err);
      }
    }

    // Fallback: remove locally
    this.scanHistory = this.scanHistory.filter(s => String(s.id) !== String(id));
    localStorage.setItem('scanHistory', JSON.stringify(this.scanHistory));
    const storedSelected = localStorage.getItem('selectedScanId');
    if (storedSelected && String(storedSelected) === String(id)) {
      localStorage.removeItem('selectedScanId');
      localStorage.removeItem('selectedScan');
    }
    this.updateDashboardTable();
  }

  async confirmDeletion(targetText) {
    return new Promise((resolve) => {
      const existing = document.querySelector('.delete-confirm-overlay');
      if (existing) existing.remove();

      const overlay = document.createElement('div');
      overlay.className = 'delete-confirm-overlay';
      overlay.style.cssText = 'position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,0.7); display:flex; align-items:center; justify-content:center; z-index:9999;';

      overlay.innerHTML = `
        <div class="delete-confirm-modal" style="background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: var(--radius-lg); padding: 2rem; max-width: 400px; color: white;">
          <div style="text-align: center; margin-bottom: 1.5rem;">
            <div style="font-size: 3rem; margin-bottom: 1rem;">⚠️</div>
            <h3 style="margin: 0 0 0.5rem 0; font-size: 1.25rem;">Delete this report?</h3>
            <p style="margin: 0; color: var(--text-muted); font-size: 0.875rem;">This action cannot be undone.</p>
          </div>
          <p style="margin: 1rem 0; color: var(--text-muted); font-size: 0.875rem;">You are about to remove <strong>${this.escapeHtml(targetText)}</strong> from your history.</p>
          <div style="display: flex; gap: 1rem; justify-content: flex-end;">
            <button class="modal-btn secondary" style="padding: 0.5rem 1rem; border: 1px solid var(--border-color); background: transparent; color: white; border-radius: var(--radius-sm); cursor: pointer;">Cancel</button>
            <button class="modal-btn danger" style="padding: 0.5rem 1rem; background: #ff4d4d; border: none; color: white; border-radius: var(--radius-sm); cursor: pointer;">Delete</button>
          </div>
        </div>
      `;

      const modal = overlay.querySelector('.delete-confirm-modal');
      const cancelBtn = overlay.querySelector('.modal-btn.secondary');
      const deleteBtn = overlay.querySelector('.modal-btn.danger');

      const cleanup = (result) => {
        overlay.remove();
        document.removeEventListener('keydown', onKey);
        resolve(result);
      };

      const onKey = (e) => {
        if (e.key === 'Escape') cleanup(false);
        if (e.key === 'Enter') cleanup(true);
      };

      overlay.addEventListener('click', (e) => {
        if (e.target === overlay) cleanup(false);
      });

      cancelBtn.addEventListener('click', () => cleanup(false));
      deleteBtn.addEventListener('click', () => cleanup(true));

      document.addEventListener('keydown', onKey);
      document.body.appendChild(overlay);
      deleteBtn.focus();
    });
  }

  /**
   * View specific scan report
   */
  viewScanReport(scanId) {
    // Find the scan
    const scan = this.scanHistory.find(s => String(s.id) === String(scanId));
    if (!scan) {
      this.showNotification('Scan not found', 'error');
      return;
    }

    localStorage.setItem('selectedScanId', String(scanId));
    try {
      // If we preserved the original server record, use that for full detail
      if (scan && scan.raw) {
        const raw = scan.raw;
        const detailed = Object.assign({}, raw, {
          id: String(raw._id || raw.id || scan.id),
          timestamp: raw.checkedAt ? new Date(raw.checkedAt).getTime() : (raw.timestamp || Date.now())
        });
        // sanitize common fields
        try {
          detailed.summary = (detailed.summary && String(detailed.summary).toLowerCase() !== 'undefined') ? detailed.summary : '';
          detailed.riskLevel = (detailed.riskLevel && String(detailed.riskLevel).toLowerCase() !== 'undefined') ? detailed.riskLevel : (detailed.risk || null);
          if (detailed.indicators && Array.isArray(detailed.indicators)) {
            detailed.indicators = detailed.indicators.map(i => (i && String(i).toLowerCase() !== 'undefined') ? i : null).filter(i=>i!==null);
          }
          if (detailed.issues && Array.isArray(detailed.issues)) {
            detailed.issues = detailed.issues.map(i => (i && String(i).toLowerCase() !== 'undefined') ? i : null).filter(i=>i!==null);
          }
        } catch (e) {}
        localStorage.setItem('selectedScan', JSON.stringify(detailed));
      } else {
        localStorage.setItem('selectedScan', JSON.stringify(scan));
      }
    } catch (e) {
      localStorage.setItem('selectedScan', JSON.stringify(scan));
    }

    // Navigate to reports page
    window.location.href = `reports.html?scanId=${scanId}`;
  }

  /**
   * Initialize reports page
   */
  initReportsPage() {
    // Get scan ID from URL parameter
    const params = new URLSearchParams(window.location.search);
    const scanId = params.get('scanId');

    if (scanId) {
      // Load specific scan
      const scan = this.scanHistory.find(s => String(s.id) === String(scanId));
      if (scan) {
        this.currentScan = scan;
        this.displayReportPage(scan);
      }
    } else if (this.scanHistory.length > 0) {
      // Load latest scan
      this.currentScan = this.scanHistory[0];
      this.displayReportPage(this.currentScan);
    } else {
      // Show empty state
      this.displayReportEmpty();
    }

    // Setup buttons
    this.setupReportButtons();
  }

  /**
   * Display report page
   */
  displayReportPage(scan) {
    const mainReport = document.getElementById('main-report');
    const recentScansList = document.getElementById('recent-scans-list');

    if (!mainReport) return;

    // Remove empty state if exists
    const emptyState = mainReport.querySelector('.empty-state');
    if (emptyState) emptyState.remove();

    // Display main report
    mainReport.innerHTML = this.generateReportHTML(scan, true);

    // Display recent scans sidebar (3 most recent excluding current)
    const recentScans = this.scanHistory.slice(1, 4);
    if (recentScansList) {
      recentScansList.innerHTML = recentScans.map((s, index) => `
        <div class="scan-preview${index === 0 ? ' active' : ''}" data-scan-id="${s.id}" style="cursor: pointer;">
          <div class="scan-preview-title">${s.type.toUpperCase()}</div>
          <div class="scan-preview-value">${this.truncate(s.value, 25)}</div>
           <span class="scan-preview-status badge ${this.getBadgeClass(s.threat || 'safe')}">
            ${(s.threat || 'safe').toUpperCase()}
          </span>
        </div>
      `).join('');

      // Attach event listeners to preview cards
      const previewCards = recentScansList.querySelectorAll('.scan-preview');
      previewCards.forEach(card => {
        card.addEventListener('click', (e) => {
          e.preventDefault();
          const scanId = card.getAttribute('data-scan-id');
          this.switchReport(scanId);
        });
      });
    }

    // Scroll to top
    setTimeout(() => {
      window.scrollTo({ top: 0, behavior: 'smooth' });
    }, 100);
  }

  /**
   * Switch to different scan report
   */
  switchReport(scanId) {
    const scan = this.scanHistory.find(s => String(s.id) === String(scanId));
    if (scan) {
      this.currentScan = scan;
      const mainReport = document.getElementById('main-report');
      if (mainReport) {
        mainReport.innerHTML = this.generateReportHTML(scan, true);
        this.setupReportButtons();
      }

      // Update active state on preview cards
      const previewCards = document.querySelectorAll('.scan-preview');
      previewCards.forEach(card => {
        card.classList.remove('active');
        if (String(card.getAttribute('data-scan-id')) === String(scanId)) {
          card.classList.add('active');
        }
      });
    }
  }

  /**
   * Display report empty state
   */
  displayReportEmpty() {
    const mainReport = document.getElementById('main-report');
    if (mainReport) {
      mainReport.innerHTML = `
        <div class="empty-state">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="12" cy="12" r="10"></circle>
            <line x1="12" y1="8" x2="12" y2="12"></line>
            <line x1="12" y1="16" x2="12.01" y2="16"></line>
          </svg>
          <h3>No Scans Yet</h3>
          <p>Perform your first scan on the <a href="index.html">homepage</a> to view reports.</p>
        </div>
      `;
    }
  }

  /**
   * Generate report HTML
   */
  generateReportHTML(scan, isMain = false) {
    // Debug logging to check scan data
    console.log('[generateReportHTML] Scan data:', {
      hasSummary: !!scan.summary,
      hasRawSummary: !!(scan.raw && scan.raw.summary),
      summary: scan.summary,
      rawSummary: scan.raw?.summary,
      scan
    });
    
    const threatColors = {
      safe: '#00FF88',
      suspicious: '#FFC107',
      malicious: '#FF4D4D'
    };

    const threatLabels = {
      safe: 'Safe',
      suspicious: 'Suspicious',
      malicious: 'Malicious'
    };

    const threatIcons = {
      safe: '✓',
      suspicious: '⚠',
      malicious: '✕'
    };

    const threatClass = this.getBadgeClass(scan.threat);

    // Helper: extract a clean sender email if present
    const extractEmail = (text) => {
      if (!text) return '';
      try {
        let s = String(text).trim();
        s = s.replace(/^(from|sender|reply[-\s]?to)\s*[:\-]\s*/i, '');
        s = s.replace(/^from\s+/i, '');
        const m = s.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i);
        if (m) return m[0];
        const m2 = s.match(/([A-Z0-9._%+-]+)\s*@\s*([A-Z0-9.-]+)\s*\.\s*([A-Z]{2,})/i);
        if (m2) return (m2[1] + '@' + m2[2] + '.' + m2[3]).replace(/\s+/g, '');
      } catch (e) {}
      return '';
    };

    // Compute display target (prefer senderEmail or extract from details/value), never show full body in header
    let targetDisplay = '';
    const PLACEHOLDER_SENDER = 'Undefined User';
    try {
      if (String(scan.type || '').toLowerCase().includes('email')) {
        targetDisplay = scan.senderEmail || extractEmail(scan.details) || extractEmail(scan.raw && scan.raw.emailContent) || extractEmail(scan.value) || '';
        if (!targetDisplay) targetDisplay = PLACEHOLDER_SENDER;
      } else {
        targetDisplay = scan.url || scan.value || '';
      }
    } catch (e) { targetDisplay = scan.url || scan.value || ''; }

    return `
      <div class="card results-card" id="scan-report-${scan.id}">
        <div class="card-header">
          <div class="card-header-row">
            <h2 class="card-title">${scan.type === 'url' ? 'URL' : 'Email'} Scan Report</h2>
            <div style="margin-top:6px;">
              <div style="font-size:12px; color:#9CA3AF; text-transform:uppercase;">Scanned Target</div>
              <div style="font-family: monospace; font-size:14px; color: white; word-break:break-all;">${this.escapeHtml(targetDisplay || '')}</div>
            </div>
            <button class="download-scan-btn" data-scan-id="${scan.id}" title="Download as PDF">
              <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                <polyline points="7 10 12 15 17 10"></polyline>
                <line x1="12" y1="15" x2="12" y2="3"></line>
              </svg>
            </button>
          </div>
        </div>

        <div class="status-badge" style="background: linear-gradient(135deg, ${threatColors[scan.threat]}20 0%, ${threatColors[scan.threat]}10 100%); border-left: 5px solid ${threatColors[scan.threat]};">
          <div class="status-badge-row">
            <div class="status-icon" style="background:${threatColors[scan.threat]}20; border: 3px solid ${threatColors[scan.threat]};">
              <span class="status-icon-symbol">${threatIcons[scan.threat]}</span>
            </div>
            <div class="status-info">
              <p class="status-label">Threat Status</p>
              <p class="status-title" style="color: ${threatColors[scan.threat]};">${threatLabels[scan.threat]}</p>
              <p class="status-sub">Confidence: ${(()=>{const c=Number(scan.confidence);return Number.isFinite(c)?(c<=1?Math.round(c*100):Math.round(c))+'%':'N/A';})()}</p>
            </div>
          </div>
        </div>

        <div class="results-grid">
          <div class="info-item">
            <p class="info-label">Scan Date</p>
            <p class="info-value">${scan.date}</p>
          </div>
          <div class="info-item">
            <p class="info-label">Scan Time</p>
            <p class="info-value">${scan.time}</p>
          </div>
          <div class="info-item">
            <p class="info-label">Confidence Score</p>
            <p class="info-value">${(()=>{const c=Number(scan.confidence);return Number.isFinite(c)?(c<=1?Math.round(c*100):Math.round(c))+'%':'N/A';})()}</p>
          </div>
          <div class="info-item">
            <p class="info-label">Risk Level</p>
            <p class="info-value">${(function(rv){ try{ const s=String(rv||'').trim().toLowerCase(); if(s==='safe') return 'Low'; if(s==='suspicious') return 'Medium'; if(s==='malicious') return 'High'; if(['low','medium','high','critical'].includes(s)) return s.charAt(0).toUpperCase()+s.slice(1); }catch(e){} return 'Unknown'; })(scan.riskLevel)}</p>
          </div>
        </div>

        <!-- Threat Analysis Results Section -->
        ${scan.type === 'url' ? `
        <div class="section">
          <h3 class="section-title">Threat Analysis Results</h3>
          <div class="info-grid" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 1rem;">
            <div class="info-item">
              <p class="info-label">Status</p>
              <p class="info-value">${(scan.threat || 'safe').toString().toUpperCase()}</p>
            </div>
            <div class="info-item">
              <p class="info-label">Detection Engine</p>
              <p class="info-value">${scan.rawThreats && scan.rawThreats.length > 0 ? 'Threat Detection Engine' : 'Heuristic Analysis Engine'}</p>
            </div>
            <div class="info-item">
              <p class="info-label">Analyzed At</p>
              <p class="info-value">${new Date(scan.timestamp || Date.now()).toISOString().replace('T', ' ').replace('Z', ' UTC')}</p>
            </div>
          </div>
          ${scan.rawThreats && scan.rawThreats.length > 0 ? `
          <div style="margin-top: 0.75rem; display: flex; gap: 0.5rem; flex-wrap: wrap;">
            ${scan.rawThreats.map(t => `<span class="badge ${this.getBadgeClass(scan.threat)}" style="background: rgba(255,255,255,0.06); border: 1px solid var(--border-color);">${this.escapeHtml((t.type || t.threatType || '').replace(/_/g, ' '))}</span>`).join('')}
          </div>
          ` : '<p style="color: var(--text-muted); margin-top: 0.75rem;">No threat categories identified</p>'}
        </div>

        <!-- Detailed Threat Table -->
        ${scan.rawThreats && scan.rawThreats.length > 0 ? `
        <div class="section">
          <h3 class="section-title">Threat Details</h3>
          <div style="max-height: 360px; overflow: auto; border: 1px solid var(--border-color); border-radius: var(--radius-md);">
            <div style="display: grid; grid-template-columns: 1.2fr 0.8fr 1fr 1fr; gap: 0.75rem; padding: 0.75rem; position: sticky; top: 0; background: rgba(255,255,255,0.06); border-bottom: 1px solid var(--border-color); font-weight: 600;">
              <div>Threat Type</div>
              <div>Severity</div>
              <div>Platform</div>
              <div>Source</div>
            </div>
            ${scan.rawThreats.map(t => `
              <div style="display: grid; grid-template-columns: 1.2fr 0.8fr 1fr 1fr; gap: 0.75rem; padding: 0.75rem; border-bottom: 1px solid var(--border-color);">
                <div>${this.escapeHtml((t.type || t.threatType || 'UNKNOWN').replace(/_/g, ' '))}</div>
                <div>${scan.threat === 'malicious' ? 'HIGH' : scan.threat === 'suspicious' ? 'MEDIUM' : 'LOW'}</div>
                <div>${this.escapeHtml((t.platform || t.platformType || 'ANY_PLATFORM').replace(/_/g, ' '))}</div>
                <div>Threat Detection Engine</div>
              </div>
            `).join('')}
          </div>
        </div>
        ` : ''}
        ` : ''}

        <div class="section">
          <h3 class="section-title">Threat Indicators</h3>
          <ul class="indicators-list">
            ${(scan.indicators || []).map(indicator => {
              const type = (indicator || '').includes('✓') ? 'safe' : (indicator || '').includes('⚠') ? 'warning' : 'threat';
              const borderColor = type === 'threat' ? '#FF4D4D' : type === 'warning' ? '#FFC107' : '#00FF88';
              return `
                <li class="indicator-item" style="border-left-color: ${borderColor};">
                  <strong>${this.escapeHtml(indicator)}</strong>
                </li>
              `;
            }).join('')}
          </ul>
        </div>

        <div class="section">
          <h3 class="section-title">Detected Issues</h3>
          ${scan.issues && scan.issues.length > 0 ? `
          <div class="issues-table-wrapper" style="overflow-x: auto; border: 1px solid var(--border-color); border-radius: var(--radius-md); -webkit-overflow-scrolling: touch;">
            <table class="issues-table" style="width: 100%; min-width: 600px; border-collapse: collapse; background: var(--card-bg); table-layout: fixed;">
              <colgroup>
                <col style="width: 35%;">
                <col style="width: 25%;">
                <col style="width: 22%;">
                <col style="width: 18%;">
              </colgroup>
              <thead>
                <tr style="background: rgba(11, 99, 217, 0.2); border-bottom: 2px solid var(--primary);">
                  <th style="padding: 1rem; text-align: left; font-weight: 700; font-size: 0.875rem; text-transform: uppercase; letter-spacing: 0.5px; white-space: nowrap; border-right: 1px solid rgba(255,255,255,0.1);">Issue</th>
                  <th style="padding: 1rem; text-align: left; font-weight: 700; font-size: 0.875rem; text-transform: uppercase; letter-spacing: 0.5px; white-space: nowrap; border-right: 1px solid rgba(255,255,255,0.1);">Timestamp</th>
                  <th style="padding: 1rem; text-align: left; font-weight: 700; font-size: 0.875rem; text-transform: uppercase; letter-spacing: 0.5px; white-space: nowrap; border-right: 1px solid rgba(255,255,255,0.1);">Engine</th>
                  <th style="padding: 1rem; text-align: left; font-weight: 700; font-size: 0.875rem; text-transform: uppercase; letter-spacing: 0.5px; white-space: nowrap;">Metadata</th>
                </tr>
              </thead>
              <tbody>
                ${scan.issues.map(issue => `
                  <tr class="issues-row" style="border-bottom: 1px solid var(--border-color); transition: background 0.2s;">
                    <td style="padding: 1rem; vertical-align: top; word-wrap: break-word; overflow-wrap: break-word; border-right: 1px solid rgba(255,255,255,0.05);">${this.escapeHtml(issue)}</td>
                    <td style="padding: 1rem; vertical-align: top; font-size: 0.7rem; font-family: monospace; color: rgba(255,255,255,0.8); word-wrap: break-word; overflow-wrap: break-word; border-right: 1px solid rgba(255,255,255,0.05); line-height: 1.3;">${new Date(scan.timestamp || Date.now()).toISOString().replace('T', ' ').replace('Z', ' UTC')}</td>
                    <td style="padding: 1rem; vertical-align: top; font-size: 0.8rem; word-wrap: break-word; overflow-wrap: break-word; border-right: 1px solid rgba(255,255,255,0.05); line-height: 1.4;">${scan.rawThreats && scan.rawThreats.length > 0 ? 'Threat Detection Engine' : 'Heuristic Analysis Engine'}</td>
                    <td style="padding: 1rem; vertical-align: top; word-wrap: break-word; overflow-wrap: break-word; font-size: 0.85rem; color: rgba(255,255,255,0.9);">${this.escapeHtml(scan.domain || 'N/A')}</td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          </div>
          <style>
            .issues-table .issues-row:hover {
              background: rgba(11, 99, 217, 0.1) !important;
            }
            .issues-table .issues-row:last-child {
              border-bottom: none !important;
            }
          </style>
          ` : '<p style="color: var(--text-muted);">No issues recorded.</p>'}
        </div>

        <div class="summary-box">
          <h3 class="section-title">Summary</h3>
          <p class="summary-text">${this.escapeHtml(scan.summary || scan.raw?.summary || 'No summary available')}</p>
        </div>

      </div>
    `;
  }

  /**
   * Setup report buttons
   */
  setupReportButtons() {
    const printBtn = document.getElementById('print-report');
    const savePdfBtn = document.getElementById('save-pdf');

    if (printBtn) {
      printBtn.onclick = () => this.printReport();
    }

    if (savePdfBtn) {
      savePdfBtn.onclick = () => this.exportReport();
    }
  }

  /**
   * Print report (only the report content, not entire page)
   */
  printReport() {
    if (!this.currentScan) {
      this.showNotification('No report to print', 'error');
      return;
    }

    const mainReport = document.getElementById('main-report');
    if (!mainReport) return;

    // Store original content
    const originalContent = document.body.innerHTML;
    const reportContent = mainReport.innerHTML;

    // Create print-friendly HTML
    const printHTML = `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <title>PhishNet Report</title>
        <style>
          body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Oxygen', 'Ubuntu', 'Cantarell', sans-serif;
            line-height: 1.6;
            color: #333;
            margin: 0;
            padding: 20px;
            background: white;
          }
          .card { 
            border: 1px solid #ddd; 
            border-radius: 8px; 
            padding: 20px; 
            margin-bottom: 20px;
            background: white;
          }
          .card-header { 
            margin-bottom: 20px; 
            border-bottom: 2px solid #0B63D9;
            padding-bottom: 10px;
          }
          h2 { 
            margin: 0 0 10px 0; 
            color: #0B63D9;
          }
          .badge { 
            display: inline-block; 
            padding: 5px 10px; 
            border-radius: 4px; 
            font-weight: bold;
            font-size: 12px;
          }
          .badge-safe { background: #00FF88; color: #000; }
          .badge-suspicious { background: #FFC107; color: #000; }
          .badge-malicious { background: #FF4D4D; color: white; }
          .grid { 
            display: grid; 
            grid-template-columns: 1fr 1fr; 
            gap: 20px; 
            margin-bottom: 20px;
          }
          .grid-item { padding: 10px; background: #f5f5f5; border-radius: 4px; }
          .grid-item p { margin: 5px 0; }
          .grid-item strong { display: block; margin-bottom: 5px; }
          ul { 
            list-style: none; 
            padding: 0; 
            margin: 0;
          }
          li { 
            padding: 8px 0; 
            border-left: 4px solid #0B63D9; 
            padding-left: 12px;
            margin-bottom: 8px;
          }
          .text-muted { color: #666; }
          @page { size: A4; margin: 1cm; }
          @media print { 
            body { margin: 0; padding: 0; }
            .card { box-shadow: none; page-break-inside: avoid; }
          }
        </style>
      </head>
      <body>
        ${reportContent}
      </body>
      </html>
    `;

    // Create new window and print
    const printWindow = window.open('', '_blank');
    printWindow.document.write(printHTML);
    printWindow.document.close();
    
    setTimeout(() => {
      printWindow.print();
    }, 250);
  }

  /**
   * Export report as PDF (using HTML2PDF library or as structured HTML)
   */
  async exportReport() {
    if (!this.currentScan) {
      this.showNotification('No report to export', 'error');
      return;
    }

    const scan = this.currentScan;
    const date = new Date();
    const filename = `PhishNet_Report_${scan.type}_${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')}.pdf`;

    // Check if we have the PDF download function available
    if (typeof window.downloadScanReportAsPDF === 'function') {
      await window.downloadScanReportAsPDF('main-report', filename, this);
    } else {
      this.showNotification('PDF download not available', 'error');
    }
  }

  /**
   * Generate full report HTML for download
   */
  generateFullReportHTML(scan) {
    const threatColor = {
      safe: '#00FF88',
      suspicious: '#FFC107',
      malicious: '#FF4D4D'
    }[scan.threat];

    return `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>PhishNet Scan Report</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { 
      font-family: "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      line-height: 1.6;
      color: #333;
      background: #f5f5f5;
      padding: 20px;
    }
    .container {
      max-width: 900px;
      margin: 0 auto;
      background: white;
      padding: 40px;
      border-radius: 8px;
      box-shadow: 0 2px 8px rgba(0,0,0,0.1);
    }
    .header {
      text-align: center;
      margin-bottom: 30px;
      border-bottom: 2px solid #0B63D9;
      padding-bottom: 20px;
    }
    .logo { font-size: 28px; font-weight: 700; color: #0B63D9; margin-bottom: 10px; }
    h1 { font-size: 24px; color: #333; margin-bottom: 10px; }
    h2 { font-size: 18px; color: #333; margin: 20px 0 15px 0; border-bottom: 2px solid #0B63D9; padding-bottom: 10px; }
    .status-section { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin: 20px 0; }
    .status-box { padding: 20px; background: #f9f9f9; border-left: 4px solid #0B63D9; border-radius: 4px; }
    .status-label { font-size: 12px; color: #666; margin-bottom: 10px; font-weight: 600; text-transform: uppercase; }
    .status-value { font-size: 24px; font-weight: 700; color: ${threatColor}; margin-bottom: 10px; }
    .info-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin: 20px 0; }
    .info-item { padding: 12px; background: #f9f9f9; border-left: 3px solid #0B63D9; border-radius: 4px; }
    .info-label { font-size: 12px; color: #666; margin-bottom: 5px; font-weight: 600; text-transform: uppercase; }
    .info-value { font-size: 14px; color: #333; font-weight: 600; word-break: break-all; }
    ul { list-style: none; padding: 0; margin: 15px 0; }
    ul li { margin-bottom: 10px; }
    .summary-box { padding: 15px; background: #f0f7ff; border-left: 4px solid #0B63D9; border-radius: 4px; margin: 20px 0; }
    .footer { text-align: center; margin-top: 40px; padding-top: 20px; border-top: 1px solid #eee; color: #999; font-size: 12px; }
    @media print { body { background: white; padding: 0; } .container { box-shadow: none; } }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="logo">PhishNet</div>
      <h1>Security Scan Report</h1>
      <p style="color: #999; margin: 10px 0 0 0;">Generated on ${scan.date} at ${scan.time}</p>
    </div>

    <h2>Scan Status</h2>
    <div class="status-section">
      <div class="status-box">
        <div class="status-label">Threat Assessment</div>
        <div class="status-value">${scan.threat.toUpperCase()}</div>
      </div>
      <div class="status-box">
        <div class="status-label">Confidence Score</div>
        <div class="status-value">${(()=>{const c=Number(scan.confidence);return Number.isFinite(c)?(c<=1?Math.round(c*100):Math.round(c))+'%':'N/A';})()}</div>
      </div>
    </div>

    <h2>Scan Information</h2>
    <div class="info-grid">
      <div class="info-item">
        <div class="info-label">Scan Type</div>
        <div class="info-value">${scan.type === 'url' ? 'URL Scan' : 'Email Scan'}</div>
      </div>
      <div class="info-item">
        <div class="info-label">Risk Level</div>
        <div class="info-value">${(function(rv){ try{ const s=String(rv||'').trim().toLowerCase(); if(s==='safe') return 'Low'; if(s==='suspicious') return 'Medium'; if(s==='malicious') return 'High'; if(['low','medium','high','critical'].includes(s)) return s.charAt(0).toUpperCase()+s.slice(1); }catch(e){} return rv || 'Unknown'; })(scan.riskLevel)}</div>
      </div>
      <div class="info-item">
        <div class="info-label">Target</div>
        <div class="info-value">${this.escapeHtml(scan.senderEmail || (function(raw){ try{ const m=String(raw).match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i); return m?m[0]:raw;}catch(e){return raw;}})(scan.value))}</div>
      </div>
      <div class="info-item">
        <div class="info-label">Scan Date</div>
        <div class="info-value">${scan.date} at ${scan.time}</div>
      </div>
    </div>

    <h2>Threat Indicators</h2>
    <ul>
      ${(scan.indicators || []).map(indicator => `<li>• ${this.escapeHtml(indicator)}</li>`).join('')}
    </ul>

    <h2>Detected Issues</h2>
    <ul>
      ${(scan.issues || []).map(issue => `<li>• ${this.escapeHtml(issue)}</li>`).join('')}
    </ul>

    <h2>Summary</h2>
    <div class="summary-box">
      <p>${this.escapeHtml(scan.summary)}</p>
    </div>

    <div class="footer">
      <p>PhishNet Security Report | Generated on ${new Date().toLocaleString()}</p>
      <p>This report is confidential and for authorized use only.</p>
    </div>
  </div>
</body>
</html>`;
  }

  /**
   * Get badge class for threat level
   */
  getBadgeClass(threat) {
    return threat === 'safe' ? 'badge-safe' : 
           threat === 'suspicious' ? 'badge-suspicious' : 
           'badge-malicious';
  }

  /**
   * Truncate text
   */
  truncate(str, length) {
    const s = String(str || '');
    return s.length > length ? s.substring(0, length) + '...' : s;
  }

  /**
   * Escape HTML
   */
  escapeHtml(text) {
    if (text == null) return '';
    const div = document.createElement('div');
    div.textContent = String(text);
    return div.innerHTML;
  }

  /**
   * Extract email address from content
   */
  extractEmailAddress(emailContent) {
    const emailRegex = /([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.[a-zA-Z0-9_-]+)/gi;
    const matches = emailContent.match(emailRegex);
    return matches ? matches[0] : 'Unknown sender';
  }

  /**
   * Show notification
   */
  showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    const bgColor = type === 'success' ? '#00FF88' : type === 'error' ? '#FF4D4D' : '#0B63D9';
    const textColor = type === 'success' ? '#000' : 'white';
    notification.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      padding: 15px 20px;
      background: ${bgColor};
      color: ${textColor};
      border-radius: 6px;
      font-weight: 600;
      font-size: 14px;
      z-index: 9999;
      animation: slideIn 0.3s ease-out;
    `;
    notification.textContent = message;
    document.body.appendChild(notification);

    setTimeout(() => {
      notification.style.animation = 'slideOut 0.3s ease-out';
      setTimeout(() => notification.remove(), 300);
    }, 3000);
  }
}

// Add animations to document
const animationStyle = document.createElement('style');
animationStyle.textContent = `
  @keyframes slideDown {
    from {
      opacity: 0;
      transform: translateY(-20px);
    }
    to {
      opacity: 1;
      transform: translateY(0);
    }
  }

  @keyframes slideUp {
    from {
      opacity: 1;
      transform: translateY(0);
    }
    to {
      opacity: 0;
      transform: translateY(-20px);
    }
  }

  @keyframes slideIn {
    from {
      transform: translateX(400px);
      opacity: 0;
    }
    to {
      transform: translateX(0);
      opacity: 1;
    }
  }

  @keyframes slideOut {
    from {
      transform: translateX(0);
      opacity: 1;
    }
    to {
      transform: translateX(400px);
      opacity: 0;
    }
  }

  .scan-preview {
    cursor: pointer;
    transition: all 0.3s ease;
  }

  .scan-preview:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 12px rgba(11, 99, 217, 0.2);
  }

  .view-report-btn:hover {
    opacity: 0.8;
  }

  .results-section {
    animation: slideDown 0.3s ease-out;
  }
`;
document.head.appendChild(animationStyle);

// Initialize the scanning system when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
  window.scanSystem = new ScanningSystem();
});
