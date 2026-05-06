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
        if (typeof window.refreshDashboardData === 'function') window.refreshDashboardData();
      }).catch((err) => {
        console.error('[ScanningSystem] Failed to load history before init:', err);
        // Fallback to init anyway
        this.init();
        if (typeof window.refreshDashboardData === 'function') window.refreshDashboardData();
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

      // Refresh scan history when user navigates back to dashboard (bfcache/tab switch)
      const self = this;
      document.addEventListener('visibilitychange', function dashVisRefresh() {
        if (document.visibilityState === 'visible' && window.location.pathname.includes('dashboard.html')) {
          console.log('[ScanningSystem] Dashboard became visible - refreshing scan history');
          self.loadScanHistory().then(() => {
            self.updateDashboardTable();
            if (typeof window.refreshDashboardData === 'function') window.refreshDashboardData();
          }).catch(() => {});
        }
      });
      // Also handle bfcache (back/forward navigation)
      window.addEventListener('pageshow', function(e) {
        if (e.persisted && window.location.pathname.includes('dashboard.html')) {
          console.log('[ScanningSystem] Page restored from bfcache - refreshing scan history');
          self.loadScanHistory().then(() => {
            self.updateDashboardTable();
            if (typeof window.refreshDashboardData === 'function') window.refreshDashboardData();
          }).catch(() => {});
        }
      });
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
    if (threatLevel === 'unsafe' || threatLevel === 'phishing' || threatLevel === 'threat') return 'malicious';
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

      const response = await fetch(getApiUrlWithParams(window.API_CONFIG.api.endpoints.users.history, { limit: 500 }), {
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
                confidence: item.confidence ?? (item.threatScore != null ? (item.status === 'safe' ? Math.max(0, 100 - item.threatScore) : Math.min(100, Math.max(item.threatScore, 50))) : (() => { const t = (item.threatLevel || item.threat || item.status || '').toString().toLowerCase(); if (t === 'safe') return 95; if (['unsafe','phishing','threat','high','critical','malicious'].includes(t)) return 85; if (['medium','suspicious','low'].includes(t)) return 70; return null; })()),
                timestamp: new Date(item.checkedAt || item.timestamp || item.createdAt || Date.now()).getTime(),
                date: new Date(item.checkedAt || item.timestamp || item.createdAt || Date.now()).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' }),
                time: new Date(item.checkedAt || item.timestamp || item.createdAt || Date.now()).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: true }),
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
              const localIsEmail = String(local.type || '').toLowerCase().includes('email');
              const duplicate = serverItems.some(srv => {
                const srvTs = Number(srv.timestamp) || 0;
                // For email scans: server stores senderEmail as value, local stores full body.
                // Match by senderEmail + close timestamp OR by value match.
                if (localIsEmail && String(srv.type || '').toLowerCase().includes('email')) {
                  const localSender = local.senderEmail || '';
                  const srvSender = srv.senderEmail || srv.value || '';
                  if (localSender && srvSender && localSender.toLowerCase() === srvSender.toLowerCase() && Math.abs(srvTs - localTs) < 30000) return true;
                }
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
          // Store server total for stats (may be larger than loaded items)
          this.totalServerScans = data.data.total || this.scanHistory.length;
          // Merge cached rich scan data (sourceDetails, contributions, etc.)
          this._mergeRichScanCache(this.scanHistory);
          console.log(`[ScanningSystem] Loaded ${this.scanHistory.length} scans from server (with rich cache merged)`);

          // - Background sync: upload any remaining local-only entries to server -
          // This ensures scans that previously failed to save to MongoDB are retried.
          if (remainingLocal.length > 0 && token) {
            console.log(`[ScanningSystem] Background-syncing ${remainingLocal.length} local-only scans to server...`);
            const saveEndpoint = `${window.API_CONFIG?.api?.authBaseURL || 'http://localhost:5000'}${window.API_CONFIG?.api?.endpoints?.history?.saveUrl || '/api/v1/urls/check'}`;
            Promise.allSettled(remainingLocal.map(scan => {
              const body = {
                url: scan.value || scan.url || '',
                status: (scan.threat === 'safe' || scan.status === 'safe') ? 'safe' : 'unsafe',
                reasons: scan.indicators || [],
                userAction: 'visited',
                wasWarned: scan.threat !== 'safe',
                confidence: scan.confidence || null,
                threatLevel: (() => { const t = String(scan.threat || scan.threatLevel || 'safe').toLowerCase(); return { suspicious: 'medium', malicious: 'high' }[t] || (['safe','low','medium','high','critical'].includes(t) ? t : 'low'); })(),
                threatType: scan.threatType || null,
                isSafe: scan.threat === 'safe' || scan.status === 'safe',
                scanType: scan.type || 'url',
                summary: scan.summary || '',
                indicators: scan.indicators || [],
                issues: scan.issues || [],
                details: scan.details || null,
                senderEmail: scan.senderEmail || null
              };
              return fetch(saveEndpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
                body: JSON.stringify(body)
              }).catch(() => {});
            })).then(results => {
              const synced = results.filter(r => r.status === 'fulfilled').length;
              console.log(`[ScanningSystem] Background sync: ${synced}/${remainingLocal.length} local scans synced`);
              // Clear localStorage scanHistory since everything should now be on the server
              if (synced === remainingLocal.length) {
                localStorage.setItem('scanHistory', JSON.stringify(this.scanHistory));
              }
            });
          }
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
    // Signal that history loading is complete (used by dashboard-data.js waitForScanHistory)
    this._historyLoaded = true;
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
      // - Check if the scan was already persisted by the /scan route -
      // When scanUrlViaBackend returns { savedToDb: true }, the scan route
      // already wrote the record to MongoDB.  Posting again to /check would
      // create a duplicate.  In that case we only cache rich data & reload.
      const alreadySavedToDb = scan._savedToDb === true;

      if (alreadySavedToDb) {
        console.log('[ScanningSystem] Scan already saved by /scan route - skipping /check POST');
        this._cacheRichScanData(scan);
      } else {
        // Logged-in user: send scan to Auth backend (port 5000) so it's stored under the user's account
        try {
          // Use backend /api/v1/urls/check endpoint to save to MongoDB
          const isEmail = String(scan.type || '').toLowerCase().includes('email');
          const saveEndpoint = isEmail 
            ? (window.API_CONFIG.api.endpoints.history?.saveEmail || '/api/v1/urls/check')
            : (window.API_CONFIG.api.endpoints.history?.saveUrl || '/api/v1/urls/check');
          
          // Build the full URL to the backend
          const endpoint = getApiUrl(saveEndpoint);

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
                url: scan.senderEmail || extractSenderEmail(scan.value) || 'unknown@local',
                senderEmail: scan.senderEmail || extractSenderEmail(scan.value) || 'unknown@local', 
                emailContent: scan.value || '', 
                subject: scan.subject || '',
                status: commonAnalysis.isSafe ? 'safe' : 'unsafe',
                reasons: commonAnalysis.indicators || [],
                userAction: 'visited',
                wasWarned: !commonAnalysis.isSafe
              })
            : Object.assign({}, commonAnalysis, { 
                url: scan.value,
                status: commonAnalysis.isSafe ? 'safe' : 'unsafe',
                reasons: commonAnalysis.indicators || [],
                userAction: 'visited',
                wasWarned: !commonAnalysis.isSafe
              });

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
              // Cache rich scan data (sourceDetails, contributions, etc.) locally
              // so reports page can display technical details even though the
              // server DB only stores basic fields.
              this._cacheRichScanData(scan);
            }
          }
        } catch (err) {
          console.error('[ScanningSystem] Error while saving scan to server, saving locally instead', err);
          this.saveScanToLocal(scan);
        }
      }

      // Always reload scan history from server after a scan so the dashboard
      // reflects the latest data (regardless of which save path succeeded)
      try {
        await this.loadScanHistory();
      } catch (e) {
        console.warn('[ScanningSystem] Failed to reload history after save:', e);
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

  /**
   * Cache rich scan data (sourceDetails, contributions, explanation, errors)
   * in localStorage so the reports page can display detailed technical info.
   * Server DB only stores basic fields; this fills the gap.
   */
  _cacheRichScanData(scan) {
    try {
      const key = (scan.value || scan.url || '').toString().trim().toLowerCase();
      if (!key) return;
      const richFields = {};
      if (scan.sourceDetails && scan.sourceDetails.length > 0) richFields.sourceDetails = scan.sourceDetails;
      if (scan.contributions && Object.keys(scan.contributions).length > 0) richFields.contributions = scan.contributions;
      if (scan.explanation) richFields.explanation = scan.explanation;
      if (scan.errors && scan.errors.length > 0) richFields.errors = scan.errors;
      if (scan.deescalated !== undefined) richFields.deescalated = scan.deescalated;
      if (scan.sources && scan.sources.length > 0) richFields.sources = scan.sources;
      if (scan.rawThreats && scan.rawThreats.length > 0) richFields.rawThreats = scan.rawThreats;
      if (scan.riskPercent !== undefined) richFields.riskPercent = scan.riskPercent;
      if (scan.riskScore !== undefined) richFields.riskScore = scan.riskScore;
      if (scan.confidence !== undefined && scan.confidence !== null) richFields.confidence = scan.confidence;
      if (Object.keys(richFields).length === 0) return;
      richFields._cachedAt = Date.now();

      // Load existing cache (max 50 entries)
      let cache = {};
      try { cache = JSON.parse(localStorage.getItem('_richScanCache') || '{}'); } catch (e) { cache = {}; }
      cache[key] = richFields;
      // Prune old entries (keep most recent 50)
      const entries = Object.entries(cache);
      if (entries.length > 50) {
        entries.sort((a, b) => (b[1]._cachedAt || 0) - (a[1]._cachedAt || 0));
        cache = Object.fromEntries(entries.slice(0, 50));
      }
      localStorage.setItem('_richScanCache', JSON.stringify(cache));
    } catch (e) {
      console.warn('[ScanningSystem] Failed to cache rich scan data:', e);
    }
  }

  /**
   * Merge cached rich data into scan items loaded from server
   */
  _mergeRichScanCache(scanItems) {
    try {
      const cache = JSON.parse(localStorage.getItem('_richScanCache') || '{}');
      if (Object.keys(cache).length === 0) return;
      for (const item of scanItems) {
        const key = (item.value || item.url || '').toString().trim().toLowerCase();
        const cached = cache[key];
        if (!cached) continue;
        // Only merge fields that don't already exist on the item
        if (cached.sourceDetails && !item.sourceDetails) item.sourceDetails = cached.sourceDetails;
        if (cached.contributions && !item.contributions) item.contributions = cached.contributions;
        if (cached.explanation && !item.explanation) item.explanation = cached.explanation;
        if (cached.errors && !item.errors) item.errors = cached.errors;
        if (cached.deescalated !== undefined && item.deescalated === undefined) item.deescalated = cached.deescalated;
        if (cached.sources && !item.sources) item.sources = cached.sources;
        if (cached.rawThreats && (!item.rawThreats || item.rawThreats.length === 0)) item.rawThreats = cached.rawThreats;
        if (cached.riskPercent !== undefined && (item.riskPercent === undefined || item.riskPercent === null)) item.riskPercent = cached.riskPercent;
        if (cached.riskScore !== undefined && (item.riskScore === undefined || item.riskScore === null)) item.riskScore = cached.riskScore;
        if (cached.confidence !== undefined && cached.confidence !== null && (item.confidence === undefined || item.confidence === null)) item.confidence = cached.confidence;
      }
    } catch (e) {
      console.warn('[ScanningSystem] Failed to merge rich scan cache:', e);
    }
  }

  saveScanToLocal(scan) {
    // Cache rich data too
    this._cacheRichScanData(scan);
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
    const urlForm = document.querySelector('#hp-panel-url form') || document.querySelector('#panel-url form');
    console.log('URL form found:', !!urlForm);
    if (urlForm) {
      urlForm.addEventListener('submit', (e) => this.handleUrlScan(e));
    }

    // Email form submission
    const emailForm = document.querySelector('#hp-panel-email form') || document.querySelector('#panel-email form');
    console.log('Email form found:', !!emailForm);
    if (emailForm) {
      emailForm.addEventListener('submit', (e) => this.handleEmailScan(e));
    }

    // Email file upload handling
    this._uploadedEmailContent = null;
    this._setupEmailFileUpload();

    // Close buttons are now handled in displayResult() for dynamic results

    // View report buttons handled via report navigation
    console.log('Homepage scanning initialized -');
  }

  /**
   * Setup email file upload - drag-and-drop + file picker
   */
  _setupEmailFileUpload() {
    const dropZone = document.getElementById('email-file-drop');
    const fileInput = document.getElementById('email-file-input');
    const loadedBar = document.getElementById('email-file-loaded');
    const fileName = document.getElementById('email-file-name');
    const fileSize = document.getElementById('email-file-size');
    const removeBtn = document.getElementById('email-file-remove');
    if (!dropZone || !fileInput) return;

    const MAX_SIZE = 5 * 1024 * 1024; // 5 MB

    // Click to browse
    dropZone.addEventListener('click', () => fileInput.click());

    // Drag events
    ['dragenter', 'dragover'].forEach(evt => {
      dropZone.addEventListener(evt, (e) => { e.preventDefault(); e.stopPropagation(); dropZone.classList.add('dragover'); });
    });
    ['dragleave', 'drop'].forEach(evt => {
      dropZone.addEventListener(evt, (e) => { e.preventDefault(); e.stopPropagation(); dropZone.classList.remove('dragover'); });
    });

    // Handle drop
    dropZone.addEventListener('drop', (e) => {
      const file = e.dataTransfer?.files?.[0];
      if (file) this._processEmailFile(file, MAX_SIZE);
    });

    // Handle file picker
    fileInput.addEventListener('change', () => {
      const file = fileInput.files?.[0];
      if (file) this._processEmailFile(file, MAX_SIZE);
      fileInput.value = ''; // reset so same file can be re-selected
    });

    // Remove file
    if (removeBtn) {
      removeBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        this._clearUploadedFile();
      });
    }
  }

  /**
   * Process an uploaded email file
   */
  _processEmailFile(file, maxSize) {
    const loadedBar = document.getElementById('email-file-loaded');
    const fileNameEl = document.getElementById('email-file-name');
    const fileSizeEl = document.getElementById('email-file-size');
    const dropZone = document.getElementById('email-file-drop');
    const textarea = document.getElementById('email-input');

    if (file.size > maxSize) {
      this.showNotification('File too large - max 5 MB', 'error');
      return;
    }

    const allowed = ['.eml', '.msg', '.txt', '.mhtml', '.mht'];
    const ext = '.' + file.name.split('.').pop().toLowerCase();
    if (!allowed.includes(ext)) {
      this.showNotification('Unsupported file type. Use .eml, .msg, .txt, or .mhtml', 'error');
      return;
    }

    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target?.result;
      if (typeof content !== 'string' || !content.trim()) {
        this.showNotification('Could not read file content', 'error');
        return;
      }
      this._uploadedEmailContent = content;

      // Show loaded indicator
      if (fileNameEl) fileNameEl.textContent = file.name;
      if (fileSizeEl) fileSizeEl.textContent = this._formatFileSize(file.size);
      if (loadedBar) loadedBar.classList.add('visible');
      if (dropZone) dropZone.style.display = 'none';

      // Also populate the textarea so user can see/edit
      if (textarea) textarea.value = content;

      this.showNotification(`Loaded "${file.name}" - ready to scan`, 'success');
    };
    reader.onerror = () => {
      this.showNotification('Failed to read file', 'error');
    };
    reader.readAsText(file);
  }

  /**
   * Clear uploaded email file
   */
  _clearUploadedFile() {
    this._uploadedEmailContent = null;
    const loadedBar = document.getElementById('email-file-loaded');
    const dropZone = document.getElementById('email-file-drop');
    if (loadedBar) loadedBar.classList.remove('visible');
    if (dropZone) dropZone.style.display = '';
  }

  /**
   * Format file size in human-readable form
   */
  _formatFileSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
  }

  /**
   * Call the full 9-source threat intelligence scanner (extension backend)
   * Uses the single backend's multi-source threat intel scanner
   */
  async scanUrlViaBackend(url) {
    console.log('[scanUrlViaBackend] Sending scan request to 9-source scanner', { url });

    // - On-Device Pre-Filter: instant block for obvious phishing -
    if (window.PhishNetPreFilter?.preFilterUrl) {
      try {
        const pf = window.PhishNetPreFilter.preFilterUrl(url);
        if (pf.action === 'BLOCK') {
          console.log('[scanUrlViaBackend] - PRE-FILTER BLOCK:', pf.reason);
          return {
            success: true,
            preFiltered: true,
            savedToDb: false,
            status: pf.status || 'MALICIOUS',
            score: pf.score,
            risk_score: pf.score / 100,
            infra_risk: 0,
            lexical_risk: pf.score / 100,
            combined_risk: pf.score / 100,
            confidence: pf.score,
            threats: pf.flags.map(f => ({ source: 'Pre-Filter', type: f.type, detail: f.detail })),
            sources: ['On-Device Pre-Filter'],
            sourceDetails: [{ source: 'On-Device Pre-Filter', safe: false, details: { flags: pf.flags } }],
            contributions: { prefilter: pf.score / 100 },
            deescalated: false,
            earlyExit: pf.reason,
            temporal_risk: 0,
            temporal_trust: 0,
            domain_age_days: null,
            explanation: pf.explanation,
            errors: [],
            meta: { url, timestamp: new Date().toISOString() }
          };
        }
        if (pf.flags?.length > 0) {
          console.log('[scanUrlViaBackend] Pre-filter hints:', pf.flags.map(f => f.type).join(', '));
        }
      } catch (pfErr) {
        console.warn('[scanUrlViaBackend] Pre-filter error (continuing to backend):', pfErr.message);
      }
    }

    const token = localStorage.getItem('token');

    // Primary: use the full multi-source scanner on port 5000
    const fullScanEndpoint = '/api/v1/urls/scan';
    const fullScanUrl = getApiUrl(fullScanEndpoint);

    try {
      const response = await fetch(fullScanUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {})
        },
        body: JSON.stringify({ url })
      });

      const data = await response.json().catch(() => ({}));
      console.log('[scanUrlViaBackend] Response received', { status: response.status, ok: response.ok, data });
      if (response.ok && data.success !== false) {
        return data;
      }
      console.warn('[scanUrlViaBackend] 9-source scanner returned error');
    } catch (err) {
      console.warn('[scanUrlViaBackend] 9-source scanner unavailable:', err.message);
    }

    throw new Error('Failed to scan URL - backend unavailable');
  }

  /**
   * Normalize scan response to UI-friendly format.
   * Supports:
   *   A) 9-source threat intel response (extension backend /api/v1/urls/scan)
   *   B) Advanced URL Scanner response (isPhishing, riskLevel, riskScore)
   *   C) Legacy Safe Browsing API response (threats array)
   */
  normalizeSafeBrowsingResult(url, apiResult, elapsedMs) {
    const data = apiResult?.data || apiResult;

    // - Format A: 9-Source Threat Intel -
    if (data?.sources && data?.sourceDetails && data?.contributions) {
      const statusRaw = (data.status || 'SAFE').toUpperCase();
      const status = statusRaw === 'MALICIOUS' ? 'malicious' : statusRaw === 'SUSPICIOUS' ? 'suspicious' : 'safe';
      const score = data.score ?? Math.round((data.risk_score || 0) * 100);
      const riskScore = data.risk_score ?? (score / 100);
      const riskLevel = status === 'malicious' ? 'High' : status === 'suspicious' ? 'Medium' : 'Low';

      // Build issues from threats
      const threats = Array.isArray(data.threats) ? data.threats : [];
      let issues;
      if (status === 'safe') {
        issues = ['- No security threats detected', '- URL appears legitimate'];
      } else {
        issues = threats.length > 0
          ? threats.map(t => {
              const label = this.formatThreatTypeLabel(t.type || t.threatType || 'THREAT');
              const detail = t.detail || t.details || '';
              return `- ${label}${detail ? ': ' + detail : ''}`;
            })
          : ['- Potential security concern detected'];
      }

      // Build summary from explanation
      let summary = data.explanation || '';
      if (!summary) {
        if (status === 'safe') summary = 'All threat intelligence sources report this URL as clean.';
        else if (status === 'malicious') summary = `This URL has been flagged as malicious with a risk score of ${score}/100.`;
        else summary = `This URL shows suspicious indicators with a risk score of ${score}/100.`;
      }

      return {
        status,
        threat: status,
        threatType: status === 'malicious' ? 'phishing' : status,
        riskLevel,
        riskPercent: score,
        riskScore,
        issues,
        indicators: threats.map(t => t.type || t.threatType || 'THREAT'),
        summary,
        confidence: data.confidence || score,
        scanTime: ((elapsedMs || 0) / 1000).toFixed(2),
        domain: this.extractDomainSafe(url),
        rawThreats: threats,
        isSafe: status === 'safe',
        // Pass through ALL rich data from 9-source scanner
        sources: data.sources || [],
        sourceDetails: data.sourceDetails || [],
        contributions: data.contributions || {},
        explanation: data.explanation || '',
        deescalated: data.deescalated || false,
        errors: data.errors || [],
        meta: data.meta || {},
      };
    }
    
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
          ? safetyIndicators.map(s => `- ${s}`)
          : ['- No security threats detected', '- URL appears legitimate'];
      } else {
        // For suspicious/malicious, show risk factors as warnings
        issues = riskFactors.length > 0 
          ? riskFactors.map(f => `- ${f}`)
          : ['- Potential security concern detected'];
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
      ? threatList.map((t) => `${String(t.platform || t.platformType || 'ANY_PLATFORM').replace(/_/g, ' ')} - ${String(t.type || t.threatType || 'THREAT').replace(/_/g, ' ')}`)
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
   * Format threat type codes to human-readable labels
   */
  formatThreatTypeLabel(type) {
    const labels = {
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
      'TYPOSQUATTING': 'Domain Impersonation',
      'SUSPICIOUS_STRUCTURE': 'Suspicious URL Structure',
      'PHISHING_URL_PATTERN': 'Phishing URL Pattern',
      'DOMAIN_VERY_NEW': 'Domain Registered < 7 Days',
      'DOMAIN_NEW': 'Domain Registered < 30 Days',
      'DOMAIN_RECENT': 'Domain Registered < 90 Days',
      'REDIRECT_LOOP': 'Redirect Loop',
      'EXCESSIVE_REDIRECTS': 'Excessive Redirects',
      'CROSS_DOMAIN_REDIRECTS': 'Cross-Domain Redirects',
      'PROTOCOL_DOWNGRADE': 'HTTPS-HTTP Downgrade',
    };
    if (labels[type]) return labels[type];
    return (type || 'Unknown').replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
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

    // Show loading state in results section
    const resultsSection = document.getElementById('results-section');
    const container = document.getElementById('scan-result-container');
    if (resultsSection) resultsSection.style.display = 'block';
    if (container) {
      container.innerHTML = `
        <div class="results-card scan-loading-card">
          <div class="scan-loading">
            <div class="scan-loading-spinner"></div>
            <div class="scan-loading-text">
              <h3>Scanning URL...</h3>
              <p>Checking 9 security sources - this may take a few seconds</p>
            </div>
            <div class="scan-loading-sources">
              <span>Google Safe Browsing</span><span>VirusTotal</span><span>URLhaus</span>
              <span>AbuseIPDB</span><span>Shodan</span><span>ML Model</span>
              <span>URL Heuristics</span><span>Domain Age</span><span>Redirect Analysis</span>
            </div>
          </div>
        </div>`;
      resultsSection.scrollIntoView({ behavior: 'smooth' });
    }

    try {
      const startTime = performance.now();
      const apiResult = await this.scanUrlViaBackend(url);
      const normalized = this.normalizeSafeBrowsingResult(url, apiResult, performance.now() - startTime);

      console.log('[handleUrlScan] Normalized result', normalized);

      // If the scan route already persisted the record, pass the flag so
      // saveScan() skips the redundant POST to /check (avoids duplicates).
      const alreadySaved = !!(apiResult?.savedToDb || (apiResult?.data && apiResult.data.savedToDb));

      await this.saveScan({
        type: 'url',
        value: url,
        _savedToDb: alreadySaved,
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
      // Hide loading state on error
      if (resultsSection) resultsSection.style.display = 'none';
      if (container) container.innerHTML = '';
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
    // Use uploaded file content if available and textarea is empty
    const emailContent = email || this._uploadedEmailContent || '';
    if (!emailContent) {
      this.showNotification('Please paste email content or upload a file', 'error');
      if (submitBtn) {
        submitBtn.disabled = false;
        submitBtn.textContent = originalLabel || 'Scan Email';
        submitBtn.classList.remove('loading');
      }
      return;
    }

    console.log('[handleEmailScan] Scanning email content');

    // Show loading state with spinner
    const resultsSection = document.getElementById('results-section');
    const container = document.getElementById('scan-result-container');
    if (resultsSection) resultsSection.style.display = 'block';
    if (container) {
      container.innerHTML = `
        <div class="results-card scan-loading-card">
          <div class="scan-loading">
            <div class="scan-loading-spinner"></div>
            <div class="scan-loading-text">
              <h3>Analyzing Email...</h3>
              <p>Running PhishingDistilBERT AI model analysis</p>
            </div>
            <div class="scan-loading-sources">
              <span>ML Classification</span><span>Header Analysis</span><span>Sender Auth</span>
              <span>Domain Verification</span><span>Content Heuristics</span><span>Pattern Matching</span>
            </div>
          </div>
        </div>`;
      resultsSection.scrollIntoView({ behavior: 'smooth' });
    }

    const startTime = performance.now();
    let scanResult;
    
    try {
      // Try calling the real backend API
      scanResult = await this.scanEmailViaBackend(emailContent);
      console.log('[handleEmailScan] Backend scan result:', scanResult);
    } catch (error) {
      console.warn('[handleEmailScan] Backend unavailable, using fallback:', error.message);
      // Fallback to heuristic scan if backend is unavailable
      scanResult = this.generateEmailScanResult(emailContent);
    }
    
    const endTime = performance.now();
    scanResult.scanTime = ((endTime - startTime) / 1000).toFixed(2);

    try {
      // Save to history (refreshes from server for logged-in users)
      await this.saveScan({
        type: 'email',
        value: emailContent,
        senderEmail: scanResult.senderEmail || null,
        ...scanResult
      });
    } catch (saveErr) {
      console.warn('[handleEmailScan] Failed to save scan:', saveErr.message);
    }
    
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
    const API_BASE = window.API_CONFIG?.api?.baseURL || 'http://localhost:5000';

    // Try to parse subject from pasted email content (raw headers)
    let parsedSubject = '';
    const subjectMatch = emailContent.match(/^Subject:\s*(.+)$/im);
    if (subjectMatch) parsedSubject = subjectMatch[1].trim();
    
    const response = await fetch(`${API_BASE}/api/v1/emails/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ 
        rawEmail: emailContent
      })
    });
    
    if (!response.ok) {
      throw new Error(`Backend responded with ${response.status}`);
    }
    
    const responseData = await response.json();
    console.log('[scanEmailViaBackend] API response:', responseData);
    
    // Extract data from response (API wraps in {success, data})
    const data = responseData.data || responseData;
    
        // Convert backend response to UI format
    // Backend returns: { verdict: 'SAFE'|'SUSPICIOUS'|'MALICIOUS'|'CAUTION', score: 0-100 }
    const verdictUpper = (data.verdict || '').toUpperCase();
    const isPhishing = verdictUpper === 'MALICIOUS' || verdictUpper === 'SUSPICIOUS' || verdictUpper === 'CAUTION';
    const scoreVal = data.score || 0;
    const confidencePercent = scoreVal;
    const status = verdictUpper === 'MALICIOUS' ? 'malicious' : (verdictUpper === 'SUSPICIOUS' || verdictUpper === 'CAUTION') ? 'suspicious' : 'safe';

        // Build indicators from backend findings (headerAnalysis + bodyAnalysis)
    const allFindings = [
      ...(data.headerAnalysis?.findings || []),
      ...(data.bodyAnalysis?.findings || [])
    ];
    
    const findingIndicators = allFindings.map(f => '\u26A0\uFE0F ' + (f.detail || f.type));
    
    // Build issues list from findings
    const issues = isPhishing 
      ? [`Phishing detected (Score: ${scoreVal}/100)`, ...findingIndicators.filter(i => i.startsWith('\u26A0\uFE0F') || i.startsWith('\u2717'))]
      : findingIndicators.length > 0 
        ? findingIndicators
        : ['\u2713 No phishing indicators detected', '\u2713 Email appears safe'];

    // Build indicators (include positive markers too)
    const indicators = findingIndicators.length > 0 
      ? findingIndicators 
      : (isPhishing 
        ? ['\u26A0\uFE0F Phishing patterns detected', '\u26A0\uFE0F Suspicious content'] 
        : ['\u2713 No phishing patterns', '\u2713 Safe content']);

    // Extract sender email from backend response
    const senderEmail = data.headerAnalysis?.sender?.from || null;

    // Build summary
    const summary = isPhishing
      ? `WARNING: This email has been identified as a potential phishing attempt (Score: ${scoreVal}/100). ${findingIndicators.slice(0, 3).join('. ')}. Exercise extreme caution - do not click links or download attachments.`
      : `This email appears to be legitimate. Our PhishNet analysis found no phishing indicators. The content does not match known phishing patterns.`;

    return {
      status,
      threat: status,
      riskLevel: status === 'safe' ? 'Low' : status === 'suspicious' ? 'Medium' : 'High',
      riskPercent: scoreVal,
      issues,
      indicators,
      summary,
      confidence: confidencePercent,
      isSafe: !isPhishing,
      isVerifiedLegitimate: data.headerAnalysis?.isVerifiedLegit || false,
      senderEmail,
      subject: parsedSubject || data.bodyAnalysis?.subject || '',
      detectionMethod: 'hybrid-ml-heuristic',
      model: 'PhishNet Hybrid Engine',
      heuristicScore: data.bodyAnalysis?.score || 0,
      headerScore: data.headerAnalysis?.score || 0,
      mlResult: null,
      riskFactors: []
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
          '- Valid SSL Certificate',
          '- Legitimate Domain Owner',
          '- No Malware Detected',
          '- Safe Redirect Pattern'
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
          '- Recently Registered Domain',
          '- Similar Domain Name Pattern',
          '- Multiple Redirects Detected',
          '- Valid Certificate'
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
          '- Malicious URL Database Match',
          '- Domain Spoofing Detected',
          '- Keylogger/Malware Signatures',
          '- Credential Harvesting Form'
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
            indicators.push(`- Verified ${brand.charAt(0).toUpperCase() + brand.slice(1)} Domain`);
            phishingScore -= 0.3;
            break;
          }
        }
      }
      
      // Authentication bonuses
      if (spfPass) {
        phishingScore -= 0.15;
        indicators.push('- SPF Passed');
      }
      if (dkimPass) {
        phishingScore -= 0.15;
        indicators.push('- DKIM Passed');
      }
      if (dmarcPass) {
        phishingScore -= 0.15;
        indicators.push('- DMARC Passed');
      }
      
      // Extra bonus if ALL authentication passed AND from verified domain
      if (spfPass && dkimPass && dmarcPass && isVerifiedLegitimate) {
        phishingScore -= 0.2;
        indicators.push('- Fully Authenticated');
      }
    }

    // Content penalty multiplier - reduced for verified legitimate emails
    const penaltyMultiplier = isVerifiedLegitimate ? 0.2 : 1.0;

    // Check for urgency keywords (reduced weight for legitimate sources)
    if (/urgent|immediately|asap|click now|verify now|act now|expire|suspended|locked|compromised/i.test(text)) {
      phishingScore += 0.2 * penaltyMultiplier;
      if (!isVerifiedLegitimate) {
        issues.push('Urgent language used to pressure action');
        indicators.push('- Urgency Language Patterns');
      }
    }

    // Check for financial keywords (some are normal in legitimate account emails)
    if (/payment|credit card|bank account|gift card|winner|prize/i.test(text)) {
      phishingScore += 0.2 * penaltyMultiplier;
      if (!isVerifiedLegitimate) {
        issues.push('Financial keywords detected');
        indicators.push('- Financial Keywords Found');
      }
    }
    
    // Password/verify are COMMON in legitimate account notification emails
    if (/password|verify|identity/i.test(text) && !isVerifiedLegitimate) {
      phishingScore += 0.15;
      issues.push('Credential keywords detected');
      indicators.push('- Credential Keywords');
    }

    // Check for suspicious URLs (only if not from verified source)
    if (!isVerifiedLegitimate && /https?:\/\/[^\s]+/i.test(text)) {
      // Check for suspicious URL patterns
      if (/secure[.-]|verify[.-]|confirm[.-]|update[.-]|\.xyz|\.info|\.top|\.click/i.test(text)) {
        phishingScore += 0.2;
        issues.push('Suspicious URL patterns detected');
        indicators.push('- Suspicious Links Detected');
      }
    }

    // Check for impersonal greetings (less relevant for verified emails)
    if (/dear customer|dear user|dear friend|valued customer|account holder/i.test(text) && !isVerifiedLegitimate) {
      phishingScore += 0.1;
      issues.push('Generic greeting detected');
      indicators.push('- Generic Greeting');
    }

    // Check for pressure tactics
    if (/do not ignore|immediate attention|time sensitive|will be suspended|lose access|act now or/i.test(text)) {
      phishingScore += 0.15 * penaltyMultiplier;
      if (!isVerifiedLegitimate) {
        issues.push('Pressure tactics to force quick action');
        indicators.push('- Pressure Tactics');
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
      indicators.unshift('- High Phishing Risk');
      summary = `ALERT: This email shows strong phishing indicators (${riskPercent}% risk). ${issues.join('. ')}. Do NOT click links or provide personal information.`;
    } else if (phishingScore >= 0.25) {
      status = 'suspicious';
      riskLevel = 'Medium';
      riskPercent = Math.round(phishingScore * 100);
      indicators.unshift('- Suspicious Content');
      summary = `This email shows warning signs (${riskPercent}% risk). ${issues.join('. ')}. Exercise caution before taking any action.`;
    } else {
      status = 'safe';
      riskLevel = 'Low';
      riskPercent = Math.round(phishingScore * 100);
      if (issues.length === 0) issues = ['No phishing indicators detected'];
      if (!indicators.some(i => i.startsWith('-'))) {
        indicators.unshift('- No Phishing Patterns');
      }
      summary = isVerifiedLegitimate 
        ? 'This email is from a verified legitimate sender with proper authentication. Safe to interact with.'
        : 'This email appears legitimate. No significant phishing indicators were detected.';
    }

    // Extract sender email from headers
    const senderMatch = emailContent.match(/from:\s*(?:.*?<([^>]+)>|([^\s\n]+@[^\s\n]+))/i);
    const senderEmail = senderMatch ? (senderMatch[1] || senderMatch[2] || '') : '';

    // Extract subject from headers
    const subjectMatch = emailContent.match(/subject:\s*(.+?)(?:\r?\n(?!\s)|$)/i);
    const subject = subjectMatch ? subjectMatch[1].trim() : '';

    return {
      status,
      riskLevel,
      riskPercent,
      issues,
      indicators,
      summary,
      confidence: Math.round((status === 'safe' ? (1 - phishingScore) : phishingScore) * 100),
      isSafe: status === 'safe',
      isVerifiedLegitimate,
      senderEmail,
      subject,
      detectionMethod: 'heuristic-only (offline)',
      heuristicScore: phishingScore,
      mlResult: { confidence: phishingScore, label: status === 'safe' ? 'legitimate' : 'phishing', inferenceTime: 0 }
    };
  }

  /**
   * Create fresh result HTML with correct status class
   * HIBP-inspired design: hero card + expandable detail sections
   */
  createResultHTML(result, resultType) {
    const threat = result.status || 'safe';
    const statusClass = `status-${threat}`;
    const score = result.riskPercent || 0;
    const isEmail = resultType === 'email';

    const verdictConfig = {
      safe: {
        title: isEmail ? 'Email Looks Safe' : 'No Threats Detected',
        description: isEmail
          ? 'This email has been analyzed by our PhishingDistilBERT AI model and heuristic engine. No phishing indicators were detected - it appears to be legitimate.'
          : 'This website has been scanned across multiple security databases and found no threats. You can visit it safely.',
        color: 'var(--color-safe)',
        rawColor: '#00FF88',
        heroGrad: 'linear-gradient(180deg, rgba(0,255,136,0.12) 0%, rgba(0,255,136,0.02) 60%, transparent 100%)'
      },
      suspicious: {
        title: isEmail ? 'Suspicious Email' : 'Suspicious Activity',
        description: isEmail
          ? 'This email shows warning signs of phishing. Avoid clicking links, downloading attachments, or sharing personal information. Review the details below.'
          : 'This website shows some warning signs. Avoid entering passwords or personal information. Review the details below to see what was detected.',
        color: 'var(--color-suspicious)',
        rawColor: '#FFC107',
        heroGrad: 'linear-gradient(180deg, rgba(255,193,7,0.12) 0%, rgba(255,193,7,0.02) 60%, transparent 100%)'
      },
      malicious: {
        title: isEmail ? 'Phishing Email Detected' : 'Malicious URL',
        description: isEmail
          ? 'This email has been identified as a phishing attempt! Do not click any links, download attachments, or reply with personal information. Delete it immediately.'
          : 'Oh no - this URL is dangerous! This website has been flagged as malicious by our security sources. Review the details below to see what was detected.',
        color: 'var(--color-malicious)',
        rawColor: '#FF4D4D',
        heroGrad: 'linear-gradient(180deg, rgba(255,77,77,0.12) 0%, rgba(255,77,77,0.02) 60%, transparent 100%)'
      }
    };

    const v = verdictConfig[threat] || verdictConfig.safe;

    // - Source stats -
    const sd = result.sourceDetails || [];
    const cleanCount = sd.filter(s => s.safe === true).length;
    const flaggedCount = sd.filter(s => s.safe === false).length;
    const errorCount = (result.errors || []).length;
    const totalSources = sd.length;

    // - HERO CARD (HIBP style - centered, big score, title, description) -
    const heroDisplayText = isEmail
      ? (result.senderEmail || result.subject || 'Email Content')
      : (result.domain || result.url || '');
    const heroCard = `
      <div class="hibp-hero ${statusClass}" style="background: ${v.heroGrad};">
        <button class="close-results-btn" title="Close results">
          <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <line x1="18" y1="6" x2="6" y2="18"></line>
            <line x1="6" y1="6" x2="18" y2="18"></line>
          </svg>
        </button>
        <div class="hibp-hero-score" style="color:${v.rawColor}">${score}</div>
        <h2 class="hibp-hero-title" style="color:${v.rawColor}">${v.title}</h2>
        <p class="hibp-hero-desc">${v.description}</p>
        <div class="hibp-hero-url">${this.escapeHtml(heroDisplayText)}</div>
      </div>`;

    // - SCAN OVERVIEW BAR (like "Stay Protected" bar) -
    const hasDetailedData = sd.length > 0 || isEmail;
    const overviewSub = isEmail
      ? `Analyzed in ${result.scanTime || '?'}s using PhishingDistilBERT AI + Heuristic Engine`
      : `Scanned in ${result.scanTime || '?'}s using ${totalSources} security sources`;
    const overviewBar = `
      <div class="hibp-overview-bar">
        <div class="hibp-overview-left">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
          <div>
            <strong>Scan Complete</strong>
            <span class="hibp-overview-sub">${overviewSub}</span>
          </div>
        </div>
        ${hasDetailedData ? `<button class="view-full-report-btn" type="button"><span class="tech-btn-label">View Details</span></button>` : ''}
      </div>`;

    // - DETAILED SECTIONS (shown/hidden on toggle, HIBP style) -
    let detailSections = '';
    if (hasDetailedData) {

      if (isEmail) {
        // ------ EMAIL-SPECIFIC DETAIL SECTIONS ------
        const emailIndicators = result.indicators || [];
        const emailIssues = result.issues || [];
        const mlResult = result.mlResult || {};
        const heuristicScore = result.heuristicScore || 0;
        const detectionMethod = result.detectionMethod || 'Unknown';

        // 1. "What Was Found" + "Analysis Overview" side-by-side
        let emailFindingsHTML = '';
        if (threat === 'safe') {
          emailFindingsHTML = `
            <p style="color:var(--text-muted);line-height:1.7;margin:0">
              Our PhishingDistilBERT AI model and heuristic analysis engine found no phishing indicators in this email.
              The content appears legitimate with no suspicious patterns, urgency tactics, or credential harvesting attempts detected.
            </p>`;
        } else {
          if (emailIssues.length > 0) {
            emailFindingsHTML = emailIssues.map(issue => `
              <p style="color:var(--text-muted);line-height:1.7;margin:0 0 0.75rem">
                <span style="color:${v.rawColor}">-</span> ${this.escapeHtml(issue)}
              </p>`).join('');
          } else {
            emailFindingsHTML = `
              <p style="color:var(--text-muted);line-height:1.7;margin:0">
                ${threat === 'malicious'
                  ? 'Multiple indicators suggest this is a phishing email designed to steal your credentials or personal information.'
                  : 'Some characteristics of this email raised concerns. Exercise caution before interacting with it.'}
              </p>`;
          }
        }

        const emailOverview = `
          <div class="hibp-detail-card hibp-overview-sidebar">
            <h3 class="hibp-detail-title">Analysis Overview</h3>
            <div class="hibp-overview-item">
              <span class="hibp-dot" style="background:var(--accent-cyan)"></span>
              <span class="hibp-overview-label">Risk Score:</span>
              <strong style="color:${v.rawColor}">${score} / 100</strong>
            </div>
            <div class="hibp-overview-item">
              <span class="hibp-dot" style="background:var(--accent-cyan)"></span>
              <span class="hibp-overview-label">Detection:</span>
              <strong style="font-size:0.82rem">${this.escapeHtml(detectionMethod)}</strong>
            </div>
            ${mlResult.confidence !== undefined ? `<div class="hibp-overview-item">
              <span class="hibp-dot" style="background:var(--primary-blue)"></span>
              <span class="hibp-overview-label">ML Confidence:</span>
              <strong style="color:var(--primary-blue)">${(mlResult.confidence * 100).toFixed(1)}%</strong>
            </div>` : ''}
            ${mlResult.inferenceTime ? `<div class="hibp-overview-item">
              <span class="hibp-dot" style="background:var(--primary-blue)"></span>
              <span class="hibp-overview-label">Inference Time:</span>
              <strong>${mlResult.inferenceTime}ms</strong>
            </div>` : ''}
            <div class="hibp-overview-item">
              <span class="hibp-dot" style="background:${heuristicScore > 0.3 ? 'var(--color-malicious)' : 'var(--color-safe)'}"></span>
              <span class="hibp-overview-label">Heuristic Score:</span>
              <strong>${(heuristicScore * 100).toFixed(0)}%</strong>
            </div>
            ${result.isVerifiedLegitimate ? `<div class="hibp-overview-item">
              <span class="hibp-dot" style="background:var(--color-safe)"></span>
              <span class="hibp-overview-label">Verified Sender:</span>
              <strong style="color:var(--color-safe)">Yes</strong>
            </div>` : ''}
          </div>`;

        // 2. Detection Sources (ML + Heuristic)
        const emailSourceItems = [];
        // ML Model source - check if the hybrid system overrode the ML prediction
        const mlSaysPhishing = mlResult.label === 'phishing';
        const mlOverridden = (mlSaysPhishing && threat === 'safe') || (!mlSaysPhishing && threat === 'malicious');
        
        if (mlOverridden) {
          // ML was overridden by hybrid scoring - show it clearly
          const mlConfPct = mlResult.confidence !== undefined ? (mlResult.confidence * 100).toFixed(1) + '%' : '';
          emailSourceItems.push(`<div class="hibp-source-item">
            <span class="hibp-dot" style="background:var(--primary-blue)"></span>
            <span class="hibp-source-name">PhishingDistilBERT (ML)</span>
            <span class="hibp-source-status" style="color:var(--text-muted)">Overridden</span>
            <span class="hibp-source-detail">Predicted ${mlSaysPhishing ? 'phishing' : 'safe'} (${mlConfPct}) - overridden by ${result.isVerifiedLegitimate ? 'verified sender auth' : 'heuristic analysis'}</span>
          </div>`);
        } else {
          // ML agrees with the overall verdict - display normally
          const mlColor = mlSaysPhishing ? 'var(--color-malicious)' : 'var(--color-safe)';
          emailSourceItems.push(`<div class="hibp-source-item">
            <span class="hibp-dot" style="background:${mlColor}"></span>
            <span class="hibp-source-name">PhishingDistilBERT (ML)</span>
            <span class="hibp-source-status" style="color:${mlColor}">${mlSaysPhishing ? 'Phishing' : 'Safe'}</span>
            <span class="hibp-source-detail">${mlResult.confidence !== undefined ? (mlResult.confidence * 100).toFixed(1) + '% confidence' : ''}</span>
          </div>`);
        }
        
        // Heuristic engine source
        const heuristicSafe = heuristicScore < 0.3;
        emailSourceItems.push(`<div class="hibp-source-item">
          <span class="hibp-dot" style="background:${heuristicSafe ? 'var(--color-safe)' : 'var(--color-malicious)'}"></span>
          <span class="hibp-source-name">Heuristic Engine</span>
          <span class="hibp-source-status" style="color:${heuristicSafe ? 'var(--color-safe)' : 'var(--color-malicious)'}">${heuristicSafe ? 'Clean' : 'Flagged'}</span>
          <span class="hibp-source-detail">Score: ${(heuristicScore * 100).toFixed(0)}%</span>
        </div>`);
        
        // Sender Auth source (when verified)
        if (result.isVerifiedLegitimate) {
          emailSourceItems.push(`<div class="hibp-source-item">
            <span class="hibp-dot" style="background:var(--color-safe)"></span>
            <span class="hibp-source-name">Sender Authentication</span>
            <span class="hibp-source-status" style="color:var(--color-safe)">Verified</span>
            <span class="hibp-source-detail">Trusted domain with full authentication</span>
          </div>`);
        };

        // 3. Indicators Found (risk factors)
        let indicatorsSection = '';
        if (emailIndicators.length > 0 || emailIssues.length > 0) {
          const allItems = [...emailIssues, ...emailIndicators.filter(i => !emailIssues.includes(i))];
          const indicatorRows = allItems.map(item => {
            const isPositive = item.startsWith('-') || item.startsWith('-');
            const isInfo = item.startsWith('-');
            const isWarning = item.startsWith('-');
            let dotColor;
            if (isPositive) dotColor = 'var(--color-safe)';
            else if (isInfo) dotColor = 'var(--primary-blue)';
            else if (isWarning) dotColor = 'var(--color-suspicious)';
            else dotColor = 'var(--color-malicious)';
            return `<div class="hibp-source-item">
              <span class="hibp-dot" style="background:${dotColor}"></span>
              <span class="hibp-source-name" style="flex:1">${this.escapeHtml(item)}</span>
            </div>`;
          }).join('');
          indicatorsSection = `
            <div class="hibp-detail-card">
              <h3 class="hibp-detail-title">Indicators Found</h3>
              <div class="hibp-sources-grid">${indicatorRows}</div>
            </div>`;
        }

        // 4. Recommended Actions for emails
        const getIcon = (svgPath) => `<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;margin-right:8px">${svgPath}</svg>`;
      const icons = {
        shieldCheck: getIcon('<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><polyline points="9 12 11 14 15 10"></polyline>'),
        lock: getIcon('<rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path>'),
        ban: getIcon('<circle cx="12" cy="12" r="10"></circle><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"></line>'),
        search: getIcon('<circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line>'),
        shield: getIcon('<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>'),
        trash: getIcon('<polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>'),
        key: getIcon('<path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"></path>'),
        alert: getIcon('<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line>'),
        speaker: getIcon('<polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5"></polygon><path d="M19.07 4.93a10 10 10 0 1 0 14.14M15.54 8.46a5 5 0 0 1 0 7.07"></path>')
      };

      const emailActions = {
        safe: [
          { icon: icons.shieldCheck, title: 'All Clear', desc: 'No action needed. This website passed all security checks.' },
          { icon: icons.lock, title: 'Stay Protected', desc: 'Keep your browser and PhishNet extension updated for continued protection.' }
        ],
        suspicious: [
          { icon: icons.ban, title: 'Don\'t Enter Personal Data', desc: 'Avoid entering passwords, credit card numbers, or personal information on this website.' },
          { icon: icons.search, title: 'Verify the Source', desc: 'If someone sent you this link, confirm with them through a different channel that it\'s legitimate.' },
          { icon: icons.shield, title: 'Use a VPN', desc: 'If you must visit, consider using a VPN and ensure your antivirus is active.' }
        ],
        malicious: [
          { icon: icons.ban, title: 'Do NOT Visit', desc: 'This website is designed to steal your information or harm your device. Close this link immediately.' },
          { icon: icons.trash, title: 'Delete the Message', desc: 'If you received this link via email or message, delete it and block the sender.' },
          { icon: icons.key, title: 'Change Your Password', desc: 'If you already visited and entered credentials, change your password immediately on the legitimate site.' },
          { icon: icons.speaker, title: 'Report It', desc: 'Report this URL to your IT department or to Google Safe Browsing to help protect others.' }
        ]
      };
        const eActions = emailActions[threat] || emailActions.safe;
        const eActionsHTML = eActions.map(a => `
          <div class="hibp-action-item">
            <div class="hibp-action-icon">${a.icon}</div>
            <div>
              <strong>${a.title}</strong>
              <p>${a.desc}</p>
            </div>
          </div>`).join('');

        detailSections = `
          <div class="hibp-details-container">
            <div class="hibp-two-col">
              <div class="hibp-detail-card hibp-main-col">
                <h3 class="hibp-detail-title">What Was Found</h3>
                ${emailFindingsHTML}
              </div>
              ${emailOverview}
            </div>

            <div class="hibp-detail-card">
              <h3 class="hibp-detail-title">Detection Sources</h3>
              <div class="hibp-sources-grid">${emailSourceItems.join('')}</div>
            </div>

            ${indicatorsSection}

            <div class="hibp-detail-card">
              <h3 class="hibp-detail-title">Recommended Actions</h3>
              <div class="hibp-actions-grid">${eActionsHTML}</div>
            </div>
          </div>`;

      } else {
      // ------ URL-SPECIFIC DETAIL SECTIONS (original) ------

      // 1. "What Happened" + "Scan Overview" side-by-side
      let findingsHTML = '';
      if (threat === 'safe') {
        findingsHTML = `
          <p style="color:var(--text-muted);line-height:1.7;margin:0">
            All ${totalSources} security intelligence sources report this URL as clean. No phishing, malware, scam indicators, 
            or suspicious patterns were detected. The domain appears legitimate and trustworthy.
          </p>`;
      } else {
        const threats = result.rawThreats || [];
        const items = [];
        threats.forEach(t => {
          const type = (t.type || t.threatType || '').toUpperCase();
          if (type.includes('TYPOSQUAT')) items.push('This domain mimics a well-known brand name - a common tactic used by phishing websites to trick users.');
          else if (type.includes('PHISHING')) items.push('This URL has been identified as a phishing page designed to steal credentials, personal data, or financial information.');
          else if (type.includes('MALWARE') || type.includes('MALICIOUS')) items.push('This website may distribute malware or other harmful software that can compromise your device.');
          else if (type.includes('SUSPICIOUS_STRUCTURE')) items.push('The URL structure contains patterns commonly found in fraudulent websites (excessive subdomains, suspicious path segments, etc.).');
          else if (type.includes('DOMAIN_VERY_NEW') || type.includes('DOMAIN_NEW')) items.push('This domain was registered very recently, which is a common characteristic of scam and phishing websites.');
          else if (type.includes('REDIRECT') || type.includes('PROTOCOL_DOWNGRADE')) items.push('This URL redirects through suspicious intermediate destinations, potentially to evade detection.');
          else if (type.includes('NO_HTTPS') || type.includes('SSL')) items.push('This website lacks proper SSL/TLS encryption, meaning your data can be intercepted in transit.');
        });
        if (items.length === 0) {
          items.push(threat === 'malicious' ? 'Multiple security checks flagged this URL as dangerous. It may be a phishing page, contain malware, or engage in other malicious activity.' : 'Some security sources raised concerns about this URL. Exercise caution when visiting.');
        }
        findingsHTML = items.map(i => `<p style="color:var(--text-muted);line-height:1.7;margin:0 0 0.75rem">${i}</p>`).join('');
      }

      const scanOverview = `
        <div class="hibp-detail-card hibp-overview-sidebar">
          <h3 class="hibp-detail-title">Scan Overview</h3>
          <div class="hibp-overview-item">
            <span class="hibp-dot" style="background:var(--accent-cyan)"></span>
            <span class="hibp-overview-label">Risk Score:</span>
            <strong style="color:${v.rawColor}">${score} / 100</strong>
          </div>
          <div class="hibp-overview-item">
            <span class="hibp-dot" style="background:var(--accent-cyan)"></span>
            <span class="hibp-overview-label">Sources Checked:</span>
            <strong>${totalSources}</strong>
          </div>
          <div class="hibp-overview-item">
            <span class="hibp-dot" style="background:var(--color-safe)"></span>
            <span class="hibp-overview-label">Clean:</span>
            <strong style="color:var(--color-safe)">${cleanCount}</strong>
          </div>
          ${flaggedCount > 0 ? `<div class="hibp-overview-item">
            <span class="hibp-dot" style="background:var(--color-malicious)"></span>
            <span class="hibp-overview-label">Flagged:</span>
            <strong style="color:var(--color-malicious)">${flaggedCount}</strong>
          </div>` : ''}
          ${errorCount > 0 ? `<div class="hibp-overview-item">
            <span class="hibp-dot" style="background:var(--color-suspicious)"></span>
            <span class="hibp-overview-label">Errors:</span>
            <strong style="color:var(--color-suspicious)">${errorCount}</strong>
          </div>` : ''}
          ${result.deescalated ? `<div class="hibp-overview-item">
            <span class="hibp-dot" style="background:var(--primary-blue)"></span>
            <span class="hibp-overview-label">De-escalated:</span>
            <strong style="color:var(--primary-blue)">Yes</strong>
          </div>` : ''}
        </div>`;

      // 2. "Security Sources" - HIBP "Compromised Data" style
      const sourceGridItems = sd.map(src => {
        const name = src.source || 'Unknown';
        const safe = src.safe === true;
        const isError = (result.errors || []).some(e => e.source === name);
        let dotColor, statusLabel;
        if (isError) { dotColor = 'var(--color-suspicious)'; statusLabel = 'Error'; }
        else if (safe) { dotColor = 'var(--color-safe)'; statusLabel = 'Clean'; }
        else { dotColor = 'var(--color-malicious)'; statusLabel = 'Flagged'; }

        let detail = '';
        const d = src.details || {};
        if (name.includes('VirusTotal') && d.malicious !== undefined) detail = `${d.malicious}/${d.total} engines flagged`;
        else if (name.includes('AbuseIPDB') && d.abuseScore !== undefined) detail = `Abuse: ${d.abuseScore}% - ${d.totalReports} reports`;
        else if (name.includes('Shodan') && d.openPorts !== undefined) detail = `${d.openPorts} ports - ${d.vulns || 0} vulns`;
        else if (name.includes('ML Model') || name.includes('BERT')) {
          if (d.note) detail = d.note;
          else if (d.phishingScore !== undefined) detail = safe ? 'Safe' : `Phishing: ${(d.phishingScore * 100).toFixed(1)}%`;
        }
        else if (name.includes('Heuristics')) {
          const parts = [];
          if (d.typosquattingDetected) parts.push('Typosquat');
          if (d.structureIssues > 0) parts.push(`${d.structureIssues} issues`);
          if (d.note === 'Trusted domain') parts.push('Trusted');
          detail = parts.join(' - ') || (safe ? 'No issues' : 'Issues found');
        }
        else if (name.includes('Domain Age')) {
          const age = d.domainAgeDays;
          detail = (age !== null && age !== undefined) ? `${age} days old` : (d.note || 'Not found');
        }
        else if (name.includes('Redirect')) {
          detail = (d.totalHops || 0) > 0 ? `${d.totalHops} hop(s)` : 'No redirects';
        }
        else if (name.includes('Safe Browsing')) detail = safe ? 'Not blacklisted' : 'Blacklisted';
        else if (name.includes('URLhaus')) detail = safe ? 'Not in database' : 'Found in database';

        return `<div class="hibp-source-item">
          <span class="hibp-dot" style="background:${dotColor}"></span>
          <span class="hibp-source-name">${this.escapeHtml(name)}</span>
          <span class="hibp-source-status" style="color:${dotColor}">${statusLabel}</span>
          ${detail ? `<span class="hibp-source-detail">${this.escapeHtml(detail)}</span>` : ''}
        </div>`;
      }).join('');

      // 3. Risk Contributions (if not safe)
      let contribSection = '';
      if (result.contributions && threat !== 'safe') {
        const c = result.contributions;
        const h = c.heuristics || {};
        const entries = [
          { label: 'Google Safe Browsing', value: c.gsb },
          { label: 'VirusTotal', value: c.virustotal },
          { label: 'URLhaus', value: c.urlhaus },
          { label: 'AbuseIPDB', value: c.abuseipdb },
          { label: 'Shodan', value: c.shodan },
          { label: 'Domain Age', value: c.domain_age },
          { label: 'Redirect Analysis', value: c.redirect },
          { label: 'ML Model (BERT)', value: c.ml_model },
          { label: 'Typosquatting', value: h.typosquat },
          { label: 'URL Structure', value: h.structure },
          { label: 'SSL / Certificates', value: h.ssl },
          { label: 'Domain Entropy', value: h.entropy },
        ].filter(e => e.value > 0);

        if (entries.length > 0) {
          const bars = entries.map(e => {
            const pct = Math.min(100, (e.value / 1.0) * 100);
            const barColor = e.value >= 0.3 ? 'var(--color-malicious)' : e.value >= 0.1 ? 'var(--color-suspicious)' : 'var(--primary-blue)';
            return `<div class="hibp-contrib-row">
              <span class="hibp-contrib-label">${this.escapeHtml(e.label)}</span>
              <div class="hibp-contrib-bar"><div class="hibp-contrib-fill" style="width:${pct}%;background:${barColor}"></div></div>
              <span class="hibp-contrib-value">+${e.value.toFixed(3)}</span>
            </div>`;
          }).join('');
          contribSection = `
            <div class="hibp-detail-card">
              <h3 class="hibp-detail-title">Risk Contributions</h3>
              <div class="hibp-contrib-grid">${bars}</div>
            </div>`;
        }
      }

      // 4. Recommended Actions
      const getIcon = (svgPath) => `<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;margin-right:8px">${svgPath}</svg>`;
      const icons = {
        shieldCheck: getIcon('<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><polyline points="9 12 11 14 15 10"></polyline>'),
        lock: getIcon('<rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path>'),
        ban: getIcon('<circle cx="12" cy="12" r="10"></circle><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"></line>'),
        search: getIcon('<circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line>'),
        shield: getIcon('<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>'),
        trash: getIcon('<polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>'),
        key: getIcon('<path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"></path>'),
        alert: getIcon('<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line>'),
        speaker: getIcon('<polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5"></polygon><path d="M19.07 4.93a10 10 10 0 1 0 14.14M15.54 8.46a5 5 0 0 1 0 7.07"></path>')
      };

      const actionItems = {
        safe: [
          { icon: icons.shieldCheck, title: 'All Clear', desc: 'No action needed. This website passed all security checks.' },
          { icon: icons.lock, title: 'Stay Protected', desc: 'Keep your browser and PhishNet extension updated for continued protection.' }
        ],
        suspicious: [
          { icon: icons.ban, title: 'Don\'t Enter Personal Data', desc: 'Avoid entering passwords, credit card numbers, or personal information on this website.' },
          { icon: icons.search, title: 'Verify the Source', desc: 'If someone sent you this link, confirm with them through a different channel that it\'s legitimate.' },
          { icon: icons.shield, title: 'Use a VPN', desc: 'If you must visit, consider using a VPN and ensure your antivirus is active.' }
        ],
        malicious: [
          { icon: icons.ban, title: 'Do NOT Visit', desc: 'This website is designed to steal your information or harm your device. Close this link immediately.' },
          { icon: icons.trash, title: 'Delete the Message', desc: 'If you received this link via email or message, delete it and block the sender.' },
          { icon: icons.key, title: 'Change Your Password', desc: 'If you already visited and entered credentials, change your password immediately on the legitimate site.' },
          { icon: icons.speaker, title: 'Report It', desc: 'Report this URL to your IT department or to Google Safe Browsing to help protect others.' }
        ]
      };

      const actions = actionItems[threat] || actionItems.safe;
      const actionsHTML = actions.map(a => `
        <div class="hibp-action-item">
          <div class="hibp-action-icon">${a.icon}</div>
          <div>
            <strong>${a.title}</strong>
            <p>${a.desc}</p>
          </div>
        </div>`).join('');

      // 5. Analysis Explanation
      let explanationSection = '';
      if (result.explanation) {
        explanationSection = `
          <div class="hibp-detail-card">
            <h3 class="hibp-detail-title">Analysis Explanation</h3>
            <p style="color:var(--text-muted);line-height:1.7;margin:0">${this.escapeHtml(result.explanation)}</p>
          </div>`;
      }

      // 6. Source Errors
      let errorsSection = '';
      if (result.errors && result.errors.length > 0) {
        errorsSection = `
          <div class="hibp-detail-card hibp-errors-card">
            <h3 class="hibp-detail-title">Source Errors (${result.errors.length})</h3>
            ${result.errors.map(e => `<div class="hibp-error-item"><strong>${this.escapeHtml(e.source || 'Unknown')}:</strong> ${this.escapeHtml(e.error || 'Unknown error')}</div>`).join('')}
          </div>`;
      }

      detailSections = `
        <div class="hibp-details-container">
          <div class="hibp-two-col">
            <div class="hibp-detail-card hibp-main-col">
              <h3 class="hibp-detail-title">What Happened</h3>
              ${findingsHTML}
            </div>
            ${scanOverview}
          </div>

          <div class="hibp-detail-card">
            <h3 class="hibp-detail-title">Security Sources</h3>
            <div class="hibp-sources-grid">${sourceGridItems}</div>
          </div>

          ${contribSection}

          <div class="hibp-detail-card">
            <h3 class="hibp-detail-title">Recommended Actions</h3>
            <div class="hibp-actions-grid">${actionsHTML}</div>
          </div>

          ${explanationSection}
          ${errorsSection}
        </div>`;
      } // end URL branch
    } // end hasDetailedData

    return `
      <div class="hibp-scan-result ${statusClass}">
        ${heroCard}
        ${overviewBar}
        ${detailSections}
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

    // Attach "View Details" toggle button handler
    const techBtn = container?.querySelector('.view-full-report-btn');
    if (techBtn) {
      techBtn.addEventListener('click', (e) => {
        e.preventDefault();
        const wrapper = container.querySelector('.hibp-scan-result');
        if (wrapper) {
          wrapper.classList.toggle('show-details');
          const label = techBtn.querySelector('.tech-btn-label');
          if (label) {
            label.textContent = wrapper.classList.contains('show-details') ? 'Hide Details' : 'View Details';
          }
        }
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
    // Table rendering handled by DashboardDataLoader
    console.log("[ScanningSystem] Dashboard init");
  }

  /**
   * Update dashboard recent scans table
   */
  updateDashboardTable() {
    // Prefer DashboardDataLoader which has proper data sync
    if (typeof window.refreshDashboardData === 'function' && window.dashboardData) {
      window.refreshDashboardData();
      return;
    }
    const listEl = document.getElementById('scan-results-list');
    if (!listEl) return;

    const PAGE_SIZE = 6;
    if (typeof this._scanPageVisible === 'undefined') this._scanPageVisible = PAGE_SIZE;

    const countEl = document.getElementById('scan-count');
    if (countEl) countEl.textContent = `${this.scanHistory.length} scan${this.scanHistory.length !== 1 ? 's' : ''}`;

    if (this.scanHistory.length === 0) {
      listEl.innerHTML = `
        <div class="dash-scan-empty">
          <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="opacity:0.3"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/></svg>
          <p>No scan results yet.</p>
        </div>`;
      return;
    }

    // Ensure IDs exist before rendering
    this.scanHistory = this.ensureScanIds(this.scanHistory);
    localStorage.setItem('scanHistory', JSON.stringify(this.scanHistory));

    const visible = this.scanHistory.slice(0, this._scanPageVisible);
    const remaining = this.scanHistory.length - visible.length;

    listEl.innerHTML = visible.map(scan => {
      try { return this._buildScanCardHTML(scan); } catch(err) { console.error(err); return ''; }
    }).join('');

    // Show More / Show Less footer
    if (this.scanHistory.length > PAGE_SIZE) {
      const showingText = remaining > 0
        ? `Showing ${visible.length} of ${this.scanHistory.length}`
        : `Showing all ${this.scanHistory.length} scans`;
      const showMoreBtn = remaining > 0
        ? `<button class="dash-scan-show-more" id="scan-show-more">Show More (${Math.min(PAGE_SIZE, remaining)})</button>`
        : '';
      const showLessBtn = this._scanPageVisible > PAGE_SIZE
        ? `<button class="dash-scan-show-more" id="scan-show-less">Show Less</button>`
        : '';
      listEl.insertAdjacentHTML('beforeend', `
        <div class="dash-scan-footer">
          <span class="dash-scan-showing">${showingText}</span>
          <div class="dash-scan-footer-btns">${showMoreBtn}${showLessBtn}</div>
        </div>`);
      const moreBtn = document.getElementById('scan-show-more');
      if (moreBtn) moreBtn.addEventListener('click', () => {
        this._scanPageVisible += PAGE_SIZE;
        this.updateDashboardTable();
      });
      const lessBtn = document.getElementById('scan-show-less');
      if (lessBtn) lessBtn.addEventListener('click', () => {
        this._scanPageVisible = PAGE_SIZE;
        this.updateDashboardTable();
      });
    }

    // Bind click actions
    if (!this._dashboardScanListBound) {
      listEl.addEventListener('click', (e) => {
        const card = e.target.closest('.dash-scan-card');
        if (!card) return;
        const id = card.dataset.scanId;
        if (id) this.viewScanReport(id);
      });
      this._dashboardScanListBound = true;
    }
  }

  _buildScanCardHTML(scan) {
    if (!scan) return '';
    const threatMap = { safe:'safe', legitimate:'safe', suspicious:'suspicious', malicious:'malicious', phishing:'malicious' };
    const colorMap = { safe:'#00FF88', suspicious:'#FFC107', malicious:'#FF4D4D' };
    const labelMap = { safe:'Safe', suspicious:'Suspicious', malicious:'Malicious' };
    const extractEmail = (text) => { try { const m = String(text||'').match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i); return m ? m[0] : ''; } catch(e){return '';} };

    const threatVal = (scan.threat || scan.status || 'safe').toString().toLowerCase();
    const cls = threatMap[threatVal] || 'safe';
    const color = colorMap[cls] || '#888';
    const label = labelMap[cls] || threatVal;
    const confNum = (()=>{ let c = Number(scan.confidence); if (!Number.isFinite(c) || c === 0) { const t = (scan.threat || scan.status || '').toString().toLowerCase(); if (t === 'safe') c = 95; else if (t === 'malicious') c = 85; else if (t === 'suspicious') c = 70; else c = 0; } return c <= 1 && c > 0 ? Math.round(c*100) : Math.round(c); })();
    const confStr = confNum > 0 ? confNum + '%' : 'N/A';
    const isEmail = String(scan.type || '').toLowerCase().includes('email');
    const displayTarget = isEmail ? (scan.senderEmail || extractEmail(scan.value) || scan.value || '') : (scan.value || scan.url || '');
    const truncated = displayTarget.length > 50 ? displayTarget.substring(0,50) + '\u2026' : displayTarget;
    const typeIcon = isEmail
      ? '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="4" width="20" height="16" rx="2"/><path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7"/></svg>'
      : '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>';
    const timeStr = `${scan.date || ''} ${scan.time || ''}`.trim();
    const sid = this.escapeHtml(String(scan.id || scan.value || ''));

    return `
      <div class="dash-scan-card" data-scan-id="${sid}">
        <div class="dash-scan-status dash-scan-${cls}">
          <span class="dash-scan-dot" style="background:${color}"></span>
        </div>
        <div class="dash-scan-info">
          <div class="dash-scan-target" title="${this.escapeHtml(displayTarget)}">${this.escapeHtml(truncated)}</div>
          <div class="dash-scan-meta-row">
            <span class="dash-scan-type">${typeIcon} ${isEmail ? 'Email' : 'URL'}</span>
            <span class="dash-scan-time">${timeStr}</span>
          </div>
        </div>
        <div class="dash-scan-result">
          <span class="dash-scan-badge dash-scan-badge-${cls}">${label}</span>
          <div class="dash-scan-conf">
            <div class="dash-scan-conf-bar"><div class="dash-scan-conf-fill" style="width:${confNum}%;background:${color}"></div></div>
            <span class="dash-scan-conf-text">${confStr}</span>
          </div>
        </div>
      </div>`;
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
        const deleteUrl = getApiUrl(`/api/v1/urls/${id}`);
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
            <div style="font-size: 3rem; margin-bottom: 1rem;">-</div>
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
    localStorage.setItem('selectedScanTime', String(Date.now()));
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
      safe: '-',
      suspicious: '-',
      malicious: '-'
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
              <p class="status-sub">Confidence: ${(()=>{let c=Number(scan.confidence);if(!Number.isFinite(c)||c===0){const t=(scan.threat||'').toLowerCase();c=t==='safe'?95:t==='malicious'?85:t==='suspicious'?70:0;}return c>0?(c<=1?Math.round(c*100):Math.round(c))+'%':'N/A';})()}</p>
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
            <p class="info-label">Risk Score</p>
            <p class="info-value" style="color:${scan.threat === 'safe' ? '#00FF88' : scan.threat === 'malicious' ? '#FF4D4D' : '#FFC107'}">${scan.riskPercent != null ? scan.riskPercent + '/100' : (()=>{let c=Number(scan.confidence);if(!Number.isFinite(c)||c===0){const t=(scan.threat||'').toLowerCase();c=t==='safe'?95:t==='malicious'?85:t==='suspicious'?70:0;}return c>0?(c<=1?Math.round(c*100):Math.round(c))+'/100':'N/A';})()}</p>
          </div>
          <div class="info-item">
            <p class="info-label">Risk Level</p>
            <p class="info-value">${(function(rv){ try{ const s=String(rv||'').trim().toLowerCase(); if(s==='safe') return 'Low'; if(s==='suspicious') return 'Medium'; if(s==='malicious') return 'High'; if(['low','medium','high','critical'].includes(s)) return s.charAt(0).toUpperCase()+s.slice(1); }catch(e){} return 'Unknown'; })(scan.riskLevel)}</p>
          </div>
          ${scan.sourceDetails && scan.sourceDetails.length > 0 ? `<div class="info-item"><p class="info-label">Sources Checked</p><p class="info-value">${scan.sourceDetails.length} security sources</p></div>` : ''}
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
              const type = (indicator || '').includes('-') ? 'safe' : (indicator || '').includes('-') ? 'warning' : 'threat';
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

        <!-- Detailed Security Sources Grid (from 9-source scanner) -->
        ${(scan.sourceDetails && scan.sourceDetails.length > 0) ? `
        <div class="section">
          <h3 class="section-title">Security Sources Analysis (${scan.sourceDetails.length} Sources)</h3>
          <div class="src-grid" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:0.75rem;">
            ${scan.sourceDetails.map(src => {
              const name = src.source || 'Unknown';
              const safe = src.safe === true;
              const isError = (scan.errors || []).some(e => e.source === name);
              let statusText, statusCls;
              if (isError) { statusText = 'Error'; statusCls = 'src-error'; }
              else if (safe) { statusText = 'Clean'; statusCls = 'src-clean'; }
              else { statusText = 'Flagged'; statusCls = 'src-flagged'; }

              let detailLine = '';
              const d = src.details || {};
              if (name.includes('VirusTotal') && d.malicious !== undefined) detailLine = d.malicious + '/' + d.total + ' engines flagged';
              else if (name.includes('AbuseIPDB') && d.abuseScore !== undefined) detailLine = 'Abuse: ' + d.abuseScore + '% - ' + d.totalReports + ' reports';
              else if (name.includes('Shodan') && d.openPorts !== undefined) detailLine = d.openPorts + ' ports - ' + (d.vulns || 0) + ' vulns';
              else if (name.includes('ML Model') || name.includes('BERT')) {
                if (d.note) detailLine = d.note;
                else if (d.phishingScore !== undefined) detailLine = safe ? 'Safe' : 'Phishing: ' + (d.phishingScore * 100).toFixed(1) + '%';
              }
              else if (name.includes('Heuristics')) {
                const p = []; if (d.typosquattingDetected) p.push('Typosquat'); if (d.structureIssues > 0) p.push(d.structureIssues + ' issues'); if (d.note === 'Trusted domain') p.push('Trusted');
                detailLine = p.join(' - ') || (safe ? 'No issues' : 'Issues found');
              }
              else if (name.includes('Domain Age')) { const age = d.domainAgeDays; detailLine = (age != null) ? age + ' days old' : (d.note || 'Not found'); }
              else if (name.includes('Redirect')) { detailLine = (d.totalHops || 0) > 0 ? d.totalHops + ' hop(s)' : 'No redirects'; }
              else if (name.includes('Safe Browsing')) detailLine = safe ? 'Not blacklisted' : 'Blacklisted';
              else if (name.includes('URLhaus')) detailLine = safe ? 'Not in database' : 'Found in database';

              return '<div class="src-card ' + statusCls + '" style="padding:0.75rem;border-radius:8px;border:1px solid ' + (isError ? 'rgba(255,193,7,0.3)' : safe ? 'rgba(0,255,136,0.15)' : 'rgba(255,77,77,0.3)') + ';background:' + (isError ? 'rgba(255,193,7,0.05)' : safe ? 'rgba(0,255,136,0.03)' : 'rgba(255,77,77,0.05)') + '"><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;"><span style="font-weight:600;font-size:0.85rem;">' + this.escapeHtml(name) + '</span><span style="font-size:0.7rem;padding:2px 8px;border-radius:12px;font-weight:600;background:' + (isError ? 'rgba(255,193,7,0.2);color:#FFC107' : safe ? 'rgba(0,255,136,0.15);color:#00FF88' : 'rgba(255,77,77,0.2);color:#FF4D4D') + ';">' + statusText + '</span></div>' + (detailLine ? '<div style="font-size:0.75rem;color:rgba(255,255,255,0.5);">' + this.escapeHtml(detailLine) + '</div>' : '') + '</div>';
            }).join('')}
          </div>
        </div>
        ` : ''}

        <!-- Risk Contributions Breakdown -->
        ${(scan.contributions && scan.threat !== 'safe') ? (() => {
          const c = scan.contributions;
          const h = c.heuristics || {};
          const entries = [
            { label: 'Google Safe Browsing', value: c.gsb || 0 },
            { label: 'VirusTotal', value: c.virustotal || 0 },
            { label: 'URLhaus', value: c.urlhaus || 0 },
            { label: 'AbuseIPDB', value: c.abuseipdb || 0 },
            { label: 'Shodan', value: c.shodan || 0 },
            { label: 'Domain Age', value: c.domain_age || 0 },
            { label: 'Redirect Analysis', value: c.redirect || 0 },
            { label: 'ML Model (BERT)', value: c.ml_model || 0 },
            { label: 'Typosquatting', value: h.typosquat || 0 },
            { label: 'URL Structure', value: h.structure || 0 },
            { label: 'SSL / Certificates', value: h.ssl || 0 },
            { label: 'Domain Entropy', value: h.entropy || 0 },
          ].filter(e => e.value > 0);

          if (entries.length === 0) return '';
          return '<div class="section"><h3 class="section-title">Risk Contribution Breakdown</h3><div style="display:flex;flex-direction:column;gap:0.5rem;">' +
            entries.map(e => {
              const pct = Math.min(100, (e.value / 1.0) * 100);
              const color = e.value >= 0.3 ? '#FF4D4D' : e.value >= 0.1 ? '#FFC107' : '#0b63d9';
              return '<div style="display:grid;grid-template-columns:160px 1fr 60px;align-items:center;gap:0.5rem;"><span style="font-size:0.8rem;color:rgba(255,255,255,0.7);">' + this.escapeHtml(e.label) + '</span><div style="height:8px;background:rgba(255,255,255,0.06);border-radius:4px;overflow:hidden;"><div style="height:100%;width:' + pct + '%;background:' + color + ';border-radius:4px;"></div></div><span style="font-size:0.75rem;color:rgba(255,255,255,0.5);text-align:right;">+' + e.value.toFixed(3) + '</span></div>';
            }).join('') + '</div></div>';
        })() : ''}

        <!-- Analysis Explanation -->
        ${scan.explanation ? `
        <div class="section">
          <h3 class="section-title">Analysis Explanation</h3>
          <p style="color: rgba(255,255,255,0.7); font-size: 0.9rem; padding: 0.75rem; background: rgba(255,255,255,0.03); border-left: 3px solid var(--primary); border-radius: 4px;">${this.escapeHtml(scan.explanation)}</p>
        </div>
        ` : ''}

        <!-- Source Errors -->
        ${(scan.errors && scan.errors.length > 0) ? `
        <div class="section">
          <h3 class="section-title">Source Errors (${scan.errors.length})</h3>
          ${scan.errors.map(e => '<div style="padding:0.5rem 0.75rem;margin-bottom:0.5rem;background:rgba(255,193,7,0.05);border-left:3px solid #FFC107;border-radius:4px;"><strong style="color:#FFC107;">' + this.escapeHtml(e.source || 'Unknown') + ':</strong> <span style="color:rgba(255,255,255,0.6);">' + this.escapeHtml(e.error || 'Unknown error') + '</span></div>').join('')}
        </div>
        ` : ''}

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
        <div class="status-value">${(()=>{let c=Number(scan.confidence);if(!Number.isFinite(c)||c===0){const t=(scan.threat||'').toLowerCase();c=t==='safe'?95:t==='malicious'?85:t==='suspicious'?70:0;}return c>0?(c<=1?Math.round(c*100):Math.round(c))+'%':'N/A';})()}</div>
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
      ${(scan.indicators || []).map(indicator => `<li>- ${this.escapeHtml(indicator)}</li>`).join('')}
    </ul>

    <h2>Detected Issues</h2>
    <ul>
      ${(scan.issues || []).map(issue => `<li>- ${this.escapeHtml(issue)}</li>`).join('')}
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

