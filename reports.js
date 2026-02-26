// Reports Page - Dynamic Scan Data Display
class ReportsManager {
  constructor() {
    this.currentReport = null;
    this.scanHistory = [];
    this.filteredReports = [];
    this.currentFilter = null;
    console.log('[ReportsManager] Constructor called');
    this.init();
  }

  init() {
    console.log('[ReportsManager] init() called, waiting for DOMContentLoaded');
    document.addEventListener('DOMContentLoaded', async () => {
      console.log('[ReportsManager] DOMContentLoaded fired, starting load...');
      
      // Check if config.js is loaded
      console.log('[ReportsManager] API_CONFIG available:', typeof window.API_CONFIG !== 'undefined');
      console.log('[ReportsManager] getApiUrlWithParams available:', typeof window.getApiUrlWithParams === 'function');
      
      // Ensure history is loaded before rendering to avoid empty/partial UI
      await this.loadScanHistory();
      console.log('[ReportsManager] loadScanHistory complete, scanHistory.length =', this.scanHistory.length);

      // Default to latest scan
      this.currentReport = this.scanHistory[0] || null;

      // Only use stored selectedScan if it was set during THIS page navigation
      // (i.e. user clicked "View Report" from scan results and was redirected here)
      try {
        const urlParams = new URLSearchParams(window.location.search);
        const urlScanId = urlParams.get('scanId') || urlParams.get('id');
        
        if (urlScanId) {
          // Explicit URL param — find matching scan
          const byId = this.scanHistory.find(s => String(s.id) === String(urlScanId));
          if (byId) this.currentReport = byId;
        } else {
          // Check localStorage selectedScan only if it was set recently (within last 10 seconds)
          const stored = localStorage.getItem('selectedScan');
          const storedTime = Number(localStorage.getItem('selectedScanTime')) || 0;
          const isRecent = (Date.now() - storedTime) < 10000; // 10s window

          if (stored && isRecent) {
            const parsed = JSON.parse(stored);
            if (parsed && parsed.id) {
              let match = this.scanHistory.find(s => String(s.id) === String(parsed.id));
              if (!match && parsed.value) {
                const parsedTs = Number(parsed.timestamp) || 0;
                match = this.scanHistory.find(s => {
                  const sameValue = String(s.value || '').toLowerCase() === String(parsed.value || '').toLowerCase();
                  const sTs = Number(s.timestamp) || 0;
                  return sameValue && (!parsedTs || !sTs || Math.abs(sTs - parsedTs) < 60000);
                });
              }
              if (match) this.currentReport = match;
            }
          }

          // Clear stale selectedScan data to prevent it from affecting future visits
          localStorage.removeItem('selectedScan');
          localStorage.removeItem('selectedScanId');
          localStorage.removeItem('selectedScanTime');
        }
      } catch (e) {
        console.warn('Failed to parse selectedScan from localStorage', e);
      }

      this.renderReports();
      this.setupEventListeners();
      this.setupFilterListeners();
    });
  }

  sanitizeValue(val) {
    if (val === undefined || val === null) return null;
    if (typeof val === 'string') {
      const s = val.trim();
      if (s === '' || s.toLowerCase() === 'undefined' || s.toLowerCase() === 'null') return null;
      return s;
    }
    return val;
  }

  formatRisk(val) {
    if (!val && val !== 0) return null;
    const s = String(val).trim().toLowerCase();
    if (s === 'safe') return 'Low';
    if (s === 'suspicious') return 'Medium';
    if (s === 'malicious') return 'High';
    if (s === 'low' || s === 'medium' || s === 'high' || s === 'critical') return s.charAt(0).toUpperCase() + s.slice(1);
    if (s === 'unknown' || s === 'null') return null;
    return val;
  }

  getDisplayTarget(report) {
    const extractEmail = (text) => {
      if (!text) return '';
      try {
        const s = String(text);
        // Match email address pattern
        const m = s.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i);
        if (m) return m[0];
        return '';
      } catch (e) { return ''; }
    };
    
    const getFirstLine = (text) => {
      if (!text) return '';
      const lines = String(text).split(/[\r\n]+/).filter(line => line.trim().length > 0);
      return lines[0]?.trim() || '';
    };
    
    if (!report) return 'Unknown User';
    const type = (report.type || '').toString().toLowerCase();
    
    // For email scans, show ONLY the sender email address or "Unknown User" with hint
    if (type.indexOf('email') !== -1) {
      // Try senderEmail field first
      if (report.senderEmail) {
        const email = extractEmail(report.senderEmail);
        if (email) return email;
      }
      
      // Try value field
      if (report.value) {
        const email = extractEmail(report.value);
        if (email) return email;
      }
      
      // No email found - show Unknown User with first line as hint
      const firstLine = getFirstLine(report.value);
      if (firstLine && firstLine.length > 0) {
        const hint = firstLine.substring(0, 80);
        return `Unknown User - "${hint}${firstLine.length > 80 ? '...' : ''}"`;
      }
      
      return 'Unknown User';
    }
    
    // For URL scans, show the URL
    return report.value || report.url || 'Unknown Target';
  }

  /**
   * Generate professional summary based on threat level
   */
  generateProfessionalSummary(report) {
    const threat = (report.threat || 'safe').toLowerCase();
    const isEmail = (report.type || '').toLowerCase().includes('email');
    const hasThreats = report.rawThreats && report.rawThreats.length > 0;
    const hasMalware = hasThreats && report.rawThreats.some(t => (t.type || '').toUpperCase().includes('MALWARE'));
    const hasPhishing = hasThreats && report.rawThreats.some(t => {
      const type = (t.type || '').toUpperCase();
      return type.includes('SOCIAL_ENGINEERING') || type.includes('PHISHING');
    });
    const hasUnwanted = hasThreats && report.rawThreats.some(t => (t.type || '').toUpperCase().includes('UNWANTED_SOFTWARE'));

    if (isEmail) {
      if (threat === 'malicious') {
        return 'This email has been classified as a significant security threat. Our analysis has identified malicious patterns consistent with phishing attacks, social engineering attempts, or malware distribution. The sender domain, content patterns, and embedded links exhibit characteristics commonly found in cyber attacks. Immediate deletion is recommended, and users should not interact with any links or attachments.';
      } else if (threat === 'suspicious') {
        return 'This email exhibits suspicious characteristics that warrant careful review. Our detection systems have identified patterns that deviate from legitimate email communication, including potentially spoofed sender information, suspicious link patterns, or urgency-based social engineering tactics. We recommend thorough verification before taking any action requested in this email.';
      } else {
        return 'This email has passed our security screening and shows no immediate indicators of malicious intent. However, users should always exercise caution with unsolicited emails and verify sender authenticity before clicking links or downloading attachments.';
      }
    } else {
      // URL scans
      if (threat === 'safe') {
        return 'Our comprehensive security analysis has completed a thorough examination of this URL and found no indicators of malicious activity, phishing attempts, or unwanted software. The URL has passed all security checks including domain reputation analysis, SSL certificate validation, and behavioral pattern matching. This resource appears legitimate and safe for user interaction.';
      } else if (threat === 'malicious') {
        let threatDesc = 'This URL has been identified as a significant security threat and presents serious risks to users. Our advanced threat detection algorithms have flagged this resource for ';
        const threats = [];
        if (hasMalware) threats.push('malware distribution');
        if (hasPhishing) threats.push('phishing attempts designed to steal credentials');
        if (hasUnwanted && !hasMalware && !hasPhishing) threats.push('distributing unwanted software');
        
        threatDesc += threats.length > 0 ? threats.join(' and ') : 'malicious activity';
        threatDesc += '. We strongly recommend avoiding this URL entirely and blocking access through your security systems. Do not enter personal information, credentials, or download any files from this source.';
        return threatDesc;
      } else {
        // suspicious
        let suspDesc = 'This URL exhibits suspicious characteristics that warrant extreme caution. Our security analysis has detected ';
        suspDesc += hasUnwanted ? 'unwanted software patterns' : 'anomalous behavior';
        suspDesc += ' commonly associated with potentially harmful activities. While not definitively malicious, this resource shows signs of deceptive practices, unusual redirect patterns, or attempts to deliver unwanted content. We recommend thorough verification before interacting with this URL.';
        return suspDesc;
      }
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
   * Transform history data from API format to frontend format
   */
  transformHistoryData(historyItems) {
    return historyItems.map(item => {
      // URLCheckHistory schema: url, status(safe/unsafe/phishing/threat/unknown),
      // reasons[], threatScore, confidence, domain, timestamp, createdAt, wasWarned, userAction

      // --- Date: prefer timestamp > createdAt > updatedAt ---
      const dateSource = item.timestamp || item.createdAt || item.checkedAt || item.updatedAt;
      const dateObj = dateSource ? new Date(dateSource) : null;
      const dateStr = dateObj ? dateObj.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' }) : '';
      const timeStr = dateObj ? dateObj.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: true }) : '';

      // --- Threat level from status field ---
      const rawStatus = String(item.status || 'unknown').toLowerCase();
      let threat = 'safe';
      if (['unsafe', 'phishing', 'threat'].includes(rawStatus)) {
        threat = rawStatus === 'unsafe' ? 'suspicious' : 'malicious';
      } else if (rawStatus === 'unknown') {
        threat = 'safe';
      }
      // Override with explicit threatLevel if provided
      if (item.threatLevel) {
        const tl = String(item.threatLevel).toLowerCase();
        if (['safe', 'low'].includes(tl)) threat = 'safe';
        else if (['suspicious', 'medium'].includes(tl)) threat = 'suspicious';
        else if (['malicious', 'high', 'critical', 'phishing', 'danger'].includes(tl)) threat = 'malicious';
      }
      // Also use threatScore as signal
      const tScore = typeof item.threatScore === 'number' ? item.threatScore : 0;
      if (tScore >= 70) threat = 'malicious';
      else if (tScore >= 40 && threat === 'safe') threat = 'suspicious';

      // --- Risk level from threatScore ---
      let riskLevel = 'Low';
      if (tScore >= 70) riskLevel = 'High';
      else if (tScore >= 40) riskLevel = 'Medium';

      // --- Confidence ---
      const confidence = (typeof item.confidence === 'number' && item.confidence > 0) ? item.confidence : (typeof item.threatScore === 'number' && item.threatScore > 0 ? (threat === 'safe' ? Math.max(0, 100 - item.threatScore) : Math.min(100, Math.max(item.threatScore, 50))) : (threat === 'safe' ? 95 : threat === 'malicious' ? 85 : 70));

      // --- Indicators from reasons[] ---
      let indicators = item.reasons || item.indicators || [];
      if (!Array.isArray(indicators)) indicators = [];
      indicators = indicators
        .map(i => this.sanitizeValue(i))
        .filter(i => i !== null)
        .map(i => String(i).replace(/^[^a-zA-Z0-9]+/g, '').trim())
        .filter(i => i.length > 0);

      // --- Issues (alias) ---
      let issues = item.issues || [];
      if (!Array.isArray(issues)) issues = [];
      // If no explicit issues but we have reasons for unsafe, use them as issues too
      if (issues.length === 0 && indicators.length > 0 && threat !== 'safe') {
        issues = [...indicators];
      }

      const reportData = {
        id: item._id,
        type: item.scanType === 'email' || (item.senderEmail || '').includes('@') ? 'email' : 'url',
        value: item.url || item.value || '',
        senderEmail: item.senderEmail || null,
        threat: threat,
        threatType: item.threatType || null,
        confidence: confidence,
        riskLevel: riskLevel,
        threatScore: tScore,
        timestamp: dateObj ? dateObj.getTime() : Date.now(),
        date: dateStr,
        time: timeStr,
        indicators: indicators,
        issues: issues,
        rawThreats: item.threatCategories || [],
        domain: item.domain || null,
        isSafe: rawStatus === 'safe',
        wasWarned: item.wasWarned || false
      };

      const summary = this.sanitizeValue(item.summary) || '';
      reportData.summary = summary || this.generateProfessionalSummary(reportData);
      return reportData;
    });
  }

  async loadScanHistory() {
    try {
      const token = localStorage.getItem('token');
      if (!token) {
        console.log('[ReportsManager] No token found, loading from localStorage');
        // Load from localStorage for non-logged-in users
        this.scanHistory = JSON.parse(localStorage.getItem('scanHistory')) || [];
        return;
      }

      // Wait for config to be available
      if (typeof window.API_CONFIG === 'undefined' || typeof window.getApiUrlWithParams === 'undefined') {
        console.warn('[ReportsManager] API_CONFIG not loaded yet, waiting...');
        await new Promise(resolve => setTimeout(resolve, 100));
      }

      // Check again and fallback if still not available
      if (typeof window.API_CONFIG === 'undefined' || typeof window.getApiUrlWithParams === 'undefined') {
        console.error('[ReportsManager] API_CONFIG still not available, using fallback URL');
        // Fallback to direct URL
        const fallbackUrl = 'http://localhost:5000/api/users/history?limit=100';
        const response = await fetch(fallbackUrl, {
          method: 'GET',
          credentials: 'include',
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json'
          }
        });
        if (response.ok) {
          const data = await response.json();
          if (data.success) {
            const serverItems = this.transformHistoryData(data.data.history);
            // Merge local scans
            let localStored = [];
            try { localStored = JSON.parse(localStorage.getItem('scanHistory')) || []; } catch (e) { localStored = []; }
            const remainingLocal = localStored.filter(local => {
              if (!local || !local.value) return false;
              const localTs = Number(local.timestamp) || 0;
              const localIsEmail = String(local.type || '').toLowerCase().includes('email');
              return !serverItems.some(srv => {
                const srvTs = Number(srv.timestamp) || 0;
                if (localIsEmail && String(srv.type || '').toLowerCase().includes('email')) {
                  const localSender = local.senderEmail || '';
                  const srvSender = srv.senderEmail || srv.value || '';
                  if (localSender && srvSender && localSender.toLowerCase() === srvSender.toLowerCase() && Math.abs(srvTs - localTs) < 30000) return true;
                }
                return String((srv.value || '').trim()).slice(0, 200) === String((local.value || '').trim()).slice(0, 200)
                  && Math.abs(srvTs - localTs) < 5000;
              });
            });
            this.scanHistory = [...serverItems, ...remainingLocal];
            console.log('[ReportsManager] Loaded history via fallback:', serverItems.length, 'server +', remainingLocal.length, 'local');
          }
        }
        return;
      }

      const apiUrl = window.getApiUrlWithParams(window.API_CONFIG.api.endpoints.users.history, { limit: 100 });
      console.log('[ReportsManager] Fetching history from:', apiUrl);

      const response = await fetch(apiUrl, {
        method: 'GET',
        credentials: 'include',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (response.ok) {
        const data = await response.json();
        console.log('[ReportsManager] API response:', data.success, 'history count:', data.data?.history?.length || 0);
        if (data.success && data.data && data.data.history) {
          // Transform API data to match frontend format
          const serverItems = this.transformHistoryData(data.data.history);

          // Merge with local-only scans (e.g. email scans saved locally when server save failed)
          let localStored = [];
          try {
            localStored = JSON.parse(localStorage.getItem('scanHistory')) || [];
          } catch (e) { localStored = []; }

          const remainingLocal = localStored.filter(local => {
            if (!local || !local.value) return false;
            const localTs = Number(local.timestamp) || 0;
            const localIsEmail = String(local.type || '').toLowerCase().includes('email');
            return !serverItems.some(srv => {
              const srvTs = Number(srv.timestamp) || 0;
              if (localIsEmail && String(srv.type || '').toLowerCase().includes('email')) {
                const localSender = local.senderEmail || '';
                const srvSender = srv.senderEmail || srv.value || '';
                if (localSender && srvSender && localSender.toLowerCase() === srvSender.toLowerCase() && Math.abs(srvTs - localTs) < 30000) return true;
              }
              return String((srv.value || '').trim()).slice(0, 200) === String((local.value || '').trim()).slice(0, 200)
                && Math.abs(srvTs - localTs) < 5000;
            });
          });

          this.scanHistory = [...serverItems, ...remainingLocal];
          console.log(`[ReportsManager] Loaded ${serverItems.length} server + ${remainingLocal.length} local scans`);
        } else {
          console.error('[ReportsManager] Failed to load scan history:', data.message);
          // Fallback to localStorage
          try { this.scanHistory = JSON.parse(localStorage.getItem('scanHistory')) || []; } catch (e) { this.scanHistory = []; }
        }
      } else {
        if (response.status === 401) {
          console.warn('[ReportsManager] Unauthorized - clearing token and cached scan data');
          localStorage.removeItem('token');
          localStorage.removeItem('scanHistory');
          localStorage.removeItem('selectedScan');
          localStorage.removeItem('selectedScanId');
          if (window.reportsManager) window.reportsManager.scanHistory = [];
          this.scanHistory = [];
          return;
        }
        console.error('[ReportsManager] Failed to fetch scan history:', response.status);
        // Fallback to localStorage
        try { this.scanHistory = JSON.parse(localStorage.getItem('scanHistory')) || []; } catch (e) { this.scanHistory = []; }
      }
    } catch (error) {
      console.error('[ReportsManager] Error loading scan history:', error);
      // Fallback to localStorage
      try { this.scanHistory = JSON.parse(localStorage.getItem('scanHistory')) || []; } catch (e) { this.scanHistory = []; }
    }
  }

  renderReports() {
    const mainReport = document.getElementById('main-report');
    const recentScansList = document.getElementById('recent-scans-list');

    // Clear container immediately before rendering
    mainReport.innerHTML = '';
    recentScansList.innerHTML = '';

    if (this.scanHistory.length === 0) {
      // Show empty state
      mainReport.innerHTML = `
        <div class="rpt-empty">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="12" cy="12" r="10"></circle>
            <line x1="12" y1="8" x2="12" y2="12"></line>
            <line x1="12" y1="16" x2="12.01" y2="16"></line>
          </svg>
          <h3>No Scans Yet</h3>
          <p>Perform your first scan on the <a href="index.html">homepage</a> to view reports.</p>
        </div>
      `;
      return;
    }

    // Set current report to latest scan if not already set (from URL or localStorage)
    if (!this.currentReport) {
      this.currentReport = this.scanHistory[0];
    }

    // Show loading state briefly while rendering
    mainReport.innerHTML = '<div style="padding: 2rem; text-align: center; color: var(--text-muted);">Loading report...</div>';

    // Render main report
    try { console.log('[ReportsManager][TRACE] renderMainReport', { reportId: this.currentReport && (this.currentReport.id || this.currentReport._id || '(no-id)'), isEmailType: String(this.currentReport.type||'').toLowerCase().includes('email'), displayTarget: this.getDisplayTarget(this.currentReport), valueLength: this.currentReport && this.currentReport.value ? String(this.currentReport.value).length : 0 }); } catch (e) {}
    this.renderMainReport(this.currentReport, mainReport);

    // Render recent scans sidebar (previous 4 scans)
    const recentCandidates = this.scanHistory.slice(1);
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
        return '';
      } catch (e) { return ''; }
    };

    // Show recent 4 scans
    const recentScans = recentCandidates.slice(0, 4);

    const recentItemsHtml = recentScans.map((scan) => {
      const typeStr = String(scan.type || '').toLowerCase();
      const cleanedFromSender = extractEmail(scan.senderEmail) || '';
      const cleanedFromValue = extractEmail(scan.value) || '';
      const isEmail = typeStr.includes('email') || cleanedFromSender !== '' || cleanedFromValue !== '';
      
      const PLACEHOLDER_SENDER = 'Unknown User';
      let displayValue;
      
      if (isEmail) {
        const emailAddress = cleanedFromSender || cleanedFromValue || '';
        displayValue = this.truncate(emailAddress || PLACEHOLDER_SENDER, 30);
      } else {
        displayValue = this.truncate(String(scan.value || scan.url || ''), 30);
      }
      
      const threat = (scan.threat || '').toLowerCase();
      const isActive = this.currentReport && String(this.currentReport.id) === String(scan.id);
      const dotColor = threat === 'safe' ? '#00FF88' : threat === 'suspicious' ? '#FFC107' : threat === 'malicious' ? '#FF4D4D' : '#6B7280';
      const badgeBg = threat === 'safe' ? 'rgba(0,255,136,0.12)' : threat === 'suspicious' ? 'rgba(255,193,7,0.12)' : threat === 'malicious' ? 'rgba(255,77,77,0.12)' : 'rgba(107,114,128,0.12)';
      const badgeColor = dotColor;
      const typeLabel = isEmail ? 'EMAIL' : 'URL';

      return `
        <div class="rpt-scan-item ${isActive ? 'active' : ''}" data-scan-id="${scan.id}">
          <div class="rpt-scan-dot" style="background:${dotColor}"></div>
          <div class="rpt-scan-body">
            <div class="rpt-scan-url">${this.escapeHtml(displayValue)}</div>
            <div class="rpt-scan-meta">
              <span>${typeLabel}</span>
              <span class="rpt-scan-badge" style="background:${badgeBg};color:${badgeColor};">${threat.toUpperCase() || 'UNKNOWN'}</span>
            </div>
          </div>
        </div>
      `;
    }).join('');

    recentScansList.innerHTML = recentItemsHtml;

    // Attach event listeners to preview cards
    const previewCards = recentScansList.querySelectorAll('.rpt-scan-item');
    previewCards.forEach(card => {
      card.addEventListener('click', (e) => {
        e.preventDefault();
        const scanId = card.getAttribute('data-scan-id');
        this.selectReport(card, scanId);
      });
    });

    // If no recent scans, show message
    if (recentScans.length === 0) {
      recentScansList.innerHTML = '<p class="rpt-indicator-none">No additional scans</p>';
    }
  }

  renderMainReport(report, container) {
    const threatColor = this.getThreatColor(report.threat);
    const threat = (report.threat || '').toLowerCase();
    const statusSymbol = threat === 'safe' ? '✓' : threat === 'suspicious' ? '⚠' : '✕';
    const statusBg = threat === 'safe' ? 'rgba(0,255,136,0.15)' : threat === 'suspicious' ? 'rgba(255,193,7,0.15)' : 'rgba(255,77,77,0.15)';
    const badgeBg = threat === 'safe' ? 'rgba(0,255,136,0.12)' : threat === 'suspicious' ? 'rgba(255,193,7,0.12)' : 'rgba(255,77,77,0.12)';

    // Ensure dynamic styles
    if (!document.getElementById('rpt-dynamic-styles')) {
      const styleEl = document.createElement('style');
      styleEl.id = 'rpt-dynamic-styles';
      styleEl.textContent = `
        .rpt-icon-btn:active { transform: scale(0.95); }
        @keyframes slideIn { from { transform: translateX(100%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }
        @keyframes slideOut { from { transform: translateX(0); opacity: 1; } to { transform: translateX(100%); opacity: 0; } }
      `;
      document.head.appendChild(styleEl);
    }

    const indicatorsArr = report.indicators || [];
    const indicatorsHtml = indicatorsArr.length > 0 ? indicatorsArr.map((indicator) => {
      const indicatorClass = this.getIndicatorType(indicator || '');
      const dotColor = indicatorClass === 'threat' ? '#FF4D4D' : indicatorClass === 'warning' ? '#FFC107' : '#00FF88';
      return `
        <div class="rpt-indicator ${indicatorClass}">
          <div class="rpt-indicator-dot" style="background:${dotColor}"></div>
          <span>${this.escapeHtml(indicator)}</span>
        </div>
      `;
    }).join('') : '<p class="rpt-indicator-none">No indicators detected</p>';

    const issuesArr = Array.isArray(report.issues) ? report.issues : [];
    const issuesHtml = issuesArr.length > 0 ? issuesArr.map(issue => `
      <div class="rpt-issue">${this.escapeHtml(issue)}</div>
    `).join('') : '<p class="rpt-indicator-none">No issues detected</p>';

    const extractEmail = (text) => {
      if (!text) return '';
      try {
        const m = String(text).match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i);
        return m ? m[0] : '';
      } catch (e) { return ''; }
    };

    const typeLabel = (report.type || '').toLowerCase() === 'url' ? 'URL' : 'Email';

    container.innerHTML = `
      <div class="rpt-card">
        <!-- Hero -->
        <div class="rpt-hero">
          <div class="rpt-hero-info">
            <div class="rpt-hero-label">${typeLabel} Scan Report</div>
            <h2 class="rpt-hero-title">${typeLabel} Analysis</h2>
            <div class="rpt-hero-target">${this.escapeHtml(this.getDisplayTarget(report))}</div>
          </div>
          <div class="rpt-hero-actions">
            <div class="rpt-hero-status">
              <div class="rpt-status-ring" style="background:${statusBg};border:2px solid ${threatColor};">${statusSymbol}</div>
              <span class="rpt-status-badge" style="background:${badgeBg};color:${threatColor};">${threat.toUpperCase() || 'UNKNOWN'}</span>
            </div>
            <button id="download-report-btn" class="rpt-icon-btn" title="Download PDF">
              <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                <polyline points="7 10 12 15 17 10"></polyline>
                <line x1="12" y1="15" x2="12" y2="3"></line>
              </svg>
            </button>
            <button id="delete-report-btn" class="rpt-icon-btn danger" title="Delete report">
              <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <polyline points="3 6 5 6 21 6"></polyline>
                <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
                <line x1="10" y1="11" x2="10" y2="17"></line>
                <line x1="14" y1="11" x2="14" y2="17"></line>
              </svg>
            </button>
          </div>
        </div>

        <!-- Metrics -->
        <div class="rpt-metrics">
          <div>
            <div class="rpt-metric-label">Date</div>
            <div class="rpt-metric-value">${report.date || 'N/A'}</div>
          </div>
          <div>
            <div class="rpt-metric-label">Time</div>
            <div class="rpt-metric-value">${report.time || 'N/A'}</div>
          </div>
          <div>
            <div class="rpt-metric-label">Score</div>
            <div class="rpt-metric-value" style="color:${threatColor}">${typeof report.threatScore === 'number' ? report.threatScore + '/100' : 'N/A'}</div>
          </div>
          <div>
            <div class="rpt-metric-label">Confidence</div>
            <div class="rpt-metric-value">${report.confidence}%</div>
          </div>
          <div>
            <div class="rpt-metric-label">Risk</div>
            <div class="rpt-metric-value" style="color:${threatColor}">${this.formatRisk(report.riskLevel) || 'Unknown'}</div>
          </div>
        </div>

        <!-- Threat Indicators -->
        <div class="rpt-section">
          <h3 class="rpt-section-title">
            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            Threat Indicators
          </h3>
          ${indicatorsHtml}
        </div>

        <!-- Detected Issues -->
        <div class="rpt-section">
          <h3 class="rpt-section-title">
            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
            Detected Issues
          </h3>
          ${issuesHtml}
        </div>

        <!-- Summary -->
        <div class="rpt-section">
          <h3 class="rpt-section-title">
            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>
            Summary
          </h3>
          <div class="rpt-summary">${this.escapeHtml(report.summary || 'No summary available.')}</div>
        </div>
      </div>
    `;

    // Scroll to top of report
    setTimeout(() => {
      const card = container.querySelector('.rpt-card');
      if (card) card.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }, 100);

    // Debug panel
    try {
      const showDebug = localStorage.getItem('debugReports') === '1' || window.location.search.includes('debugReports=1');
      if (showDebug) {
        const debugId = 'report-debug-panel';
        let panel = document.getElementById(debugId);
        if (panel) panel.remove();
        panel = document.createElement('div');
        panel.id = debugId;
        panel.style.cssText = 'background:#0b1224;color:#e5e7eb;padding:12px;border-radius:8px;margin-top:12px;overflow:auto;max-height:200px;font-family:monospace;font-size:12px;';
        panel.innerHTML = `<details open style="color:#e5e7eb"><summary style="cursor:pointer">Raw report object (debug)</summary><pre style="white-space:pre-wrap;">${this.escapeHtml(JSON.stringify(report, null, 2))}</pre></details>`;
        const main = document.getElementById('main-report');
        if (main) main.appendChild(panel);
      }
    } catch (e) {
      console.warn('Failed to render debug panel', e);
    }
  }

  selectReport(element, reportId) {
    const report = this.scanHistory.find(r => String(r.id) === String(reportId));
    if (!report) {
      console.error('Report not found:', reportId);
      return;
    }

    this.currentReport = report;
    
    // Update active state in sidebar
    document.querySelectorAll('.rpt-scan-item').forEach(el => el.classList.remove('active'));
    element.classList.add('active');

    // Render main report
    const mainReport = document.getElementById('main-report');
    this.renderMainReport(report, mainReport);

    // Update buttons
    this.setupEventListeners();
  }

  setupEventListeners() {
    const downloadBtn = document.getElementById('download-report-btn');
    const deleteBtn = document.getElementById('delete-report-btn');

    if (downloadBtn) {
      downloadBtn.onclick = () => this.exportReport();
    }

    if (deleteBtn) {
      deleteBtn.onclick = () => this.deleteCurrentReport();
    }
  }

  async deleteCurrentReport() {
    if (!this.currentReport) return;
    
    const label = String(this.currentReport.type || '').toLowerCase().includes('email') 
      ? (this.currentReport.senderEmail || this.currentReport.value || 'this email')
      : (this.currentReport.value || this.currentReport.url || 'this URL');
    
    const confirmed = await this.confirmDeletion(label);
    if (!confirmed) return;

    const token = localStorage.getItem('token');
    if (token) {
      try {
        const deleteUrl = `${config.api.baseURL}/api/scan/${this.currentReport.id}`;
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
            // Reload history and re-render
            await this.loadScanHistory();
            this.renderReports();
            this.showNotification('Report deleted', 'info');
            return;
          }
        }
        console.warn('[ReportsManager] Server failed to delete scan');
        this.showNotification('Failed to delete report', 'error');
      } catch (err) {
        console.error('[ReportsManager] Error deleting scan:', err);
        this.showNotification('Failed to delete report', 'error');
      }
    }
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

  showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.style.cssText = `
      position: fixed;
      bottom: 2rem;
      right: 2rem;
      background: ${type === 'error' ? '#ff4d4d' : type === 'success' ? '#00ff88' : '#0b63d9'};
      color: white;
      padding: 1rem 1.5rem;
      border-radius: var(--radius-md);
      z-index: 10000;
      animation: slideIn 0.3s ease;
    `;
    notification.textContent = message;
    document.body.appendChild(notification);
    
    setTimeout(() => {
      notification.style.animation = 'slideOut 0.3s ease';
      setTimeout(() => notification.remove(), 300);
    }, 3000);
  }

  exportReport() {
    if (!this.currentReport) {
      this.showNotification('No report selected', 'error');
      return;
    }

    const report = this.currentReport;
    const date = new Date();
    const filename = `PhishNet_Report_${report.type}_${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')}.pdf`;
    
    downloadReportAsPDF('main-report', filename);
  }

  generateHtmlReport(report) {
    const threat = (report.threat || 'safe').toLowerCase();
    const statusColor = threat === 'safe' ? '#16a34a' : threat === 'suspicious' ? '#eab308' : '#dc2626';
    const heroWord = threat === 'safe' ? 'Safe.' : threat === 'suspicious' ? 'Suspicious.' : 'Malicious.';
    const badgeLabel = threat === 'safe' ? 'VERIFIED TARGET' : threat === 'suspicious' ? 'SUSPICIOUS TARGET' : 'THREAT DETECTED';
    const badgeDesc = threat === 'safe'
      ? 'No malicious signatures or behavioral anomalies detected during deep analysis.'
      : threat === 'suspicious'
      ? 'Suspicious patterns detected during analysis. Exercise caution.'
      : 'Malicious signatures or behavioral anomalies detected. Avoid this target.';
    const confidenceLabel = (report.confidence || 0) >= 80 ? 'High' : (report.confidence || 0) >= 50 ? 'Medium' : 'Low';
    const riskSub = threat === 'safe' ? 'Minimal' : threat === 'suspicious' ? 'Moderate' : 'Severe';
    const idStr = report.id ? String(report.id).substring(0, 8).toUpperCase() + '...' : 'N/A';

    // Parse URL
    let urlHost = '', urlDomain = '', urlProtocol = '', hasSsl = false;
    try {
      const u = new URL(report.value);
      urlHost = u.hostname;
      urlDomain = report.domain || urlHost.replace(/^www\\./, '');
      urlProtocol = u.protocol === 'https:' ? 'TLS 1.3' : 'HTTP';
      hasSsl = u.protocol === 'https:';
    } catch (e) {
      urlHost = report.domain || report.value || 'N/A';
      urlDomain = report.domain || 'N/A';
      urlProtocol = (report.value || '').startsWith('https') ? 'TLS 1.3' : 'HTTP';
      hasSsl = (report.value || '').startsWith('https');
    }

    // Indicator dots
    let dotItemsHtml = '';
    if (threat === 'safe') {
      dotItemsHtml = `
        <div class="dot-item"><span class="dot" style="background:${statusColor}"></span><span>Reputation: Clean</span></div>
        <div class="dot-item"><span class="dot" style="background:${statusColor}"></span><span>Malware: None</span></div>
        <div class="dot-item"><span class="dot" style="background:${statusColor}"></span><span>Phishing: Negative</span></div>`;
    } else if (threat === 'suspicious') {
      dotItemsHtml = `
        <div class="dot-item"><span class="dot" style="background:${statusColor}"></span><span>Reputation: Suspicious</span></div>
        <div class="dot-item"><span class="dot" style="background:${statusColor}"></span><span>Malware: Check Required</span></div>
        <div class="dot-item"><span class="dot" style="background:${statusColor}"></span><span>Phishing: Possible</span></div>`;
    } else {
      dotItemsHtml = `
        <div class="dot-item"><span class="dot" style="background:${statusColor}"></span><span>Reputation: Flagged</span></div>
        <div class="dot-item"><span class="dot" style="background:${statusColor}"></span><span>Malware: Detected</span></div>
        <div class="dot-item"><span class="dot" style="background:${statusColor}"></span><span>Phishing: Positive</span></div>`;
    }

    // Threat indicators section
    const indicators = report.indicators || [];
    const indicatorsSectionHtml = indicators.length > 0 ? `
      <section class="section">
        <h3 class="section-title">THREAT INDICATORS</h3>
        <div class="indicators-list">
          ${indicators.map(ind => `
            <div class="dot-item"><span class="dot" style="background:${statusColor}"></span><span>${this.escapeHtml(ind)}</span></div>
          `).join('')}
        </div>
      </section>` : '';

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
      color: #000;
      background: #fff;
    }
    .page {
      max-width: 720px;
      margin: 0 auto;
      padding: 64px 32px;
    }
    .header {
      display: flex;
      justify-content: space-between;
      align-items: flex-end;
      margin-bottom: 64px;
    }
    .header-left { display: flex; flex-direction: column; gap: 12px; }
    .brand {
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .brand-dot {
      width: 7px; height: 7px;
      background: #000;
      border-radius: 50%;
    }
    .brand-text {
      font-size: 9px;
      font-weight: 700;
      letter-spacing: 0.2em;
      text-transform: uppercase;
      color: #737373;
    }
    .report-title {
      font-size: 32px;
      font-weight: 300;
      letter-spacing: -0.02em;
      color: #000;
    }
    .report-title span { font-weight: 600; }
    .meta {
      font-family: "Courier New", monospace;
      font-size: 10px;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: #737373;
    }
    .meta-row {
      display: flex;
      justify-content: space-between;
      gap: 40px;
      padding: 4px 0;
    }
    .meta-row + .meta-row { border-top: 1px solid #e6e6e6; }
    .meta-val { color: #000; }
    .hero {
      display: flex;
      align-items: baseline;
      gap: 48px;
      margin-bottom: 32px;
      flex-wrap: wrap;
    }
    .hero-text {
      font-size: 80px;
      font-weight: 700;
      letter-spacing: -0.04em;
      line-height: 1;
      color: #000;
    }
    .hero-info { max-width: 260px; }
    .badge-label {
      font-size: 9px;
      font-weight: 700;
      letter-spacing: 0.15em;
      text-transform: uppercase;
      color: ${statusColor};
      margin-bottom: 12px;
    }
    .badge-desc {
      font-size: 13px;
      line-height: 1.6;
      color: #737373;
    }
    .stats {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 16px;
      margin-bottom: 64px;
    }
    .stat {
      border-left: 1px solid #e6e6e6;
      padding: 6px 0 6px 16px;
    }
    .stat-label {
      font-size: 8px;
      font-weight: 700;
      letter-spacing: 0.15em;
      text-transform: uppercase;
      color: #737373;
      margin-bottom: 4px;
    }
    .stat-val {
      font-size: 18px;
      font-weight: 600;
      letter-spacing: -0.01em;
    }
    .stat-sub {
      font-size: 9px;
      font-weight: 500;
      color: #737373;
      margin-left: 4px;
    }
    .section { margin-bottom: 48px; }
    .section-title {
      font-size: 10px;
      font-weight: 700;
      letter-spacing: 0.2em;
      text-transform: uppercase;
      color: #a0a0a0;
      padding-bottom: 16px;
      border-bottom: 1px solid #e6e6e6;
      margin-bottom: 24px;
    }
    .url-label {
      font-size: 8px;
      font-weight: 700;
      letter-spacing: 0.15em;
      text-transform: uppercase;
      color: #737373;
      margin-bottom: 8px;
    }
    .url-box {
      font-family: "Courier New", monospace;
      font-size: 13px;
      background: #f5f5f5;
      padding: 12px 16px;
      border-radius: 6px;
      word-break: break-all;
      margin-bottom: 32px;
    }
    .info-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 48px;
    }
    .info-row {
      display: flex;
      justify-content: space-between;
      align-items: center;
      font-size: 13px;
      padding-bottom: 8px;
      border-bottom: 1px solid #f0f0f0;
      margin-bottom: 16px;
    }
    .info-label { color: #737373; }
    .info-value { font-weight: 600; }
    .info-value.green { color: ${hasSsl ? '#16a34a' : '#000'}; }
    .assessment {
      display: flex;
      gap: 48px;
    }
    .assessment-text {
      flex: 1;
      font-size: 15px;
      font-weight: 300;
      line-height: 1.7;
      color: rgba(0,0,0,0.8);
    }
    .dot-list { width: 240px; padding-top: 4px; }
    .dot-item {
      display: flex;
      align-items: center;
      gap: 10px;
      margin-bottom: 14px;
      font-size: 11px;
      font-weight: 500;
    }
    .dot {
      width: 5px; height: 5px;
      border-radius: 50%;
      flex-shrink: 0;
    }
    .indicators-list { padding-top: 4px; }
    .footer {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding-top: 96px;
    }
    .footer-text {
      display: flex;
      align-items: center;
      gap: 24px;
      font-size: 9px;
      font-weight: 700;
      letter-spacing: 0.15em;
      text-transform: uppercase;
      color: #c0c0c0;
    }
    .shield-circle {
      width: 32px; height: 32px;
      border-radius: 50%;
      border: 1px solid #e6e6e6;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 14px;
      color: #d0d0d0;
    }
    @media (max-width: 640px) {
      .page { padding: 32px 16px; }
      .header { flex-direction: column; align-items: flex-start; gap: 24px; }
      .hero { flex-direction: column; gap: 16px; }
      .hero-text { font-size: 48px; }
      .stats { grid-template-columns: repeat(2, 1fr); }
      .info-grid { grid-template-columns: 1fr; gap: 0; }
      .assessment { flex-direction: column; gap: 24px; }
      .dot-list { width: 100%; }
      .footer { flex-direction: column; align-items: flex-start; gap: 16px; }
    }
    @media print { body { background: white; } .page { padding: 32px 0; } }
  </style>
</head>
<body>
  <div class="page">
    <!-- Header -->
    <div class="header">
      <div class="header-left">
        <div class="brand">
          <div class="brand-dot"></div>
          <span class="brand-text">PhishNet Intelligence</span>
        </div>
        <h1 class="report-title">Scan <span>Report</span></h1>
      </div>
      <div class="meta">
        <div class="meta-row">
          <span>Date</span>
          <span class="meta-val">${this.escapeHtml(report.date || 'N/A')}</span>
        </div>
        <div class="meta-row">
          <span>ID</span>
          <span class="meta-val">${idStr}</span>
        </div>
      </div>
    </div>

    <!-- Hero Result -->
    <section>
      <div class="hero">
        <div class="hero-text">${heroWord}</div>
        <div class="hero-info">
          <div class="badge-label">${badgeLabel}</div>
          <p class="badge-desc">${badgeDesc}</p>
        </div>
      </div>
      <div class="stats">
        <div class="stat">
          <div class="stat-label">Confidence</div>
          <div><span class="stat-val">${report.confidence || 0}%</span><span class="stat-sub">${confidenceLabel}</span></div>
        </div>
        <div class="stat">
          <div class="stat-label">Risk Level</div>
          <div><span class="stat-val">${this.escapeHtml(report.riskLevel || 'Low')}</span><span class="stat-sub">${riskSub}</span></div>
        </div>
        <div class="stat">
          <div class="stat-label">Threat Score</div>
          <div><span class="stat-val">${report.threatScore || 0}</span><span class="stat-sub">Score</span></div>
        </div>
        <div class="stat">
          <div class="stat-label">Encryption</div>
          <div><span class="stat-val">${hasSsl ? 'SSL' : 'None'}</span><span class="stat-sub">${hasSsl ? 'Valid' : 'N/A'}</span></div>
        </div>
      </div>
    </section>

    <!-- Target Specification -->
    <section class="section">
      <h3 class="section-title">Target Specification</h3>
      <div class="url-label">Endpoint URL</div>
      <div class="url-box">${this.escapeHtml(report.value || 'N/A')}</div>
      <div class="info-grid">
        <div>
          <div class="info-row">
            <span class="info-label">Domain</span>
            <span class="info-value">${this.escapeHtml(urlDomain)}</span>
          </div>
          <div class="info-row">
            <span class="info-label">Host</span>
            <span class="info-value">${this.escapeHtml(urlHost)}</span>
          </div>
        </div>
        <div>
          <div class="info-row">
            <span class="info-label">Protocol</span>
            <span class="info-value">${urlProtocol}</span>
          </div>
          <div class="info-row">
            <span class="info-label">Certificate</span>
            <span class="info-value green">${hasSsl ? 'Active' : 'None'}</span>
          </div>
        </div>
      </div>
    </section>

    <!-- Security Assessment -->
    <section class="section">
      <h3 class="section-title">Security Assessment</h3>
      <div class="assessment">
        <div class="assessment-text">${this.escapeHtml(report.summary || 'No summary available.')}</div>
        <div class="dot-list">${dotItemsHtml}</div>
      </div>
    </section>

    ${indicatorsSectionHtml}

    <!-- Footer -->
    <div class="footer">
      <div class="footer-text">
        <span>&copy; 2026 PhishNet</span>
        <span>Security Operations</span>
      </div>
      <div class="shield-circle">&#x1F6E1;</div>
    </div>
  </div>
</body>
</html>`;
  }

  truncate(str, length) {
    const s = String(str || '');
    return s.length > length ? s.substring(0, length) + '...' : s;
  }

  escapeHtml(text) {
    if (text == null) return '';
    const div = document.createElement('div');
    div.textContent = String(text);
    return div.innerHTML;
  }

  getThreatColor(threat) {
    return threat === 'safe' ? '#00FF88' : threat === 'suspicious' ? '#FFC107' : '#FF4D4D';
  }

  getThreatClass(threat) {
    return threat === 'safe' ? 'badge-safe' : threat === 'suspicious' ? 'badge-suspicious' : 'badge-malicious';
  }

  getIndicatorType(indicator) {
    const lower = indicator.toLowerCase();
    if (lower.includes('valid') || lower.includes('✓') || lower.includes('good')) return 'safe';
    if (lower.includes('malicious') || lower.includes('✕') || lower.includes('threat')) return 'threat';
    return 'warning';
  }

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
      z-index: 10001;
      animation: slideIn 0.3s ease-out;
    `;
    notification.textContent = message;
    document.body.appendChild(notification);

    setTimeout(() => {
      notification.style.animation = 'slideOut 0.3s ease-out';
      setTimeout(() => notification.remove(), 300);
    }, 3000);
  }

  // ======================== FILTER FUNCTIONALITY ========================
  setupFilterListeners() {
    const filterSelect = document.getElementById('report-filter-select');
    const applyFilterBtn = document.getElementById('apply-filter-btn');
    const modalCloseBtn = document.getElementById('modal-close-btn');
    const modalCloseBtn2 = document.getElementById('modal-close-btn2');
    const modalBackdrop = document.getElementById('modal-backdrop');
    const modalDownloadBtn = document.getElementById('modal-download-pdf');

    if (applyFilterBtn) {
      applyFilterBtn.addEventListener('click', () => {
        const selectedFilter = filterSelect.value;
        if (selectedFilter) {
          this.applyFilter(selectedFilter);
        } else {
          this.showNotification('Please select a time range', 'error');
        }
      });
    }

    if (modalCloseBtn) {
      modalCloseBtn.addEventListener('click', () => this.closeModal());
    }

    if (modalCloseBtn2) {
      modalCloseBtn2.addEventListener('click', () => this.closeModal());
    }

    if (modalBackdrop) {
      modalBackdrop.addEventListener('click', () => this.closeModal());
    }

    if (modalDownloadBtn) {
      modalDownloadBtn.addEventListener('click', () => this.downloadFilteredReportsPDF());
    }

    // Allow Enter key to apply filter
    if (filterSelect) {
      filterSelect.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
          applyFilterBtn.click();
        }
      });
    }

    // Close modal on Escape key
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        const modal = document.getElementById('filtered-reports-modal');
        if (modal && !modal.classList.contains('hidden')) {
          this.closeModal();
        }
      }
    });
  }

  getDateRange(filterType) {
    const now = new Date();
    let startDate = new Date();
    let displayText = '';

    switch (filterType) {
      case '7days':
        startDate.setDate(now.getDate() - 7);
        displayText = 'Last 7 Days';
        break;
      case '1month':
        startDate.setMonth(now.getMonth() - 1);
        displayText = 'Last 1 Month';
        break;
      case '2months':
        startDate.setMonth(now.getMonth() - 2);
        displayText = 'Last 2 Months';
        break;
      case '3months':
        startDate.setMonth(now.getMonth() - 3);
        displayText = 'Last 3 Months';
        break;
      case '4months':
        startDate.setMonth(now.getMonth() - 4);
        displayText = 'Last 4 Months';
        break;
      case '5months':
        startDate.setMonth(now.getMonth() - 5);
        displayText = 'Last 5 Months';
        break;
      case '6months':
        startDate.setMonth(now.getMonth() - 6);
        displayText = 'Last 6 Months';
        break;
    }

    return { startDate, endDate: now, displayText };
  }

  parseReportDate(dateString) {
    // Handle formats like "01/20/2025" or "2025-01-20"
    const formats = [
      /(\d{1,2})\/(\d{1,2})\/(\d{4})/, // MM/DD/YYYY
      /(\d{4})-(\d{1,2})-(\d{1,2})/, // YYYY-MM-DD
    ];

    for (const format of formats) {
      const match = dateString.match(format);
      if (match) {
        if (format === formats[0]) {
          // MM/DD/YYYY format
          return new Date(match[3], match[1] - 1, match[2]);
        } else {
          // YYYY-MM-DD format
          return new Date(match[1], match[2] - 1, match[3]);
        }
      }
    }

    // Fallback: try direct parsing
    return new Date(dateString);
  }

  applyFilter(filterType) {
    const { startDate, endDate, displayText } = this.getDateRange(filterType);

    // Filter reports based on date range — prefer stored timestamp for accuracy
    this.filteredReports = this.scanHistory.filter((report) => {
      const reportDate = report.timestamp ? new Date(report.timestamp) : this.parseReportDate(report.date);
      return reportDate >= startDate && reportDate <= endDate;
    });

    this.currentFilter = filterType;

    // Display filtered results in modal
    this.displayFilteredReportsInModal(displayText);
    this.showNotification(`Found ${this.filteredReports.length} reports`, 'success');
  }

  displayFilteredReportsInModal(displayText) {
    const modal = document.getElementById('filtered-reports-modal');
    const reportsList = document.getElementById('modal-reports-list');
    const emptyState = document.getElementById('modal-reports-empty');
    const modalTitle = document.getElementById('modal-period');
    console.log('[ReportsManager][TRACE] displayFilteredReportsInModal', { displayText, count: this.filteredReports.length });

    // Update modal header
    modalTitle.textContent = displayText;

    // Clear list
    reportsList.innerHTML = '';

    if (this.filteredReports.length === 0) {
      emptyState.style.display = 'block';
      this.updateModalStatistics();
      this.openModal();
      return;
    }

    emptyState.style.display = 'none';

    // Render filtered reports with detailed information
    this.filteredReports.forEach((report, index) => {
      const card = this.createDetailedModalReportCard(report, index);
      reportsList.appendChild(card);
    });

    // Update statistics
    this.updateModalStatistics();

    // Open modal
    this.openModal();
  }

  createDetailedModalReportCard(report, index) {
    const threatColor = this.getThreatColor(report.threat);
    const threatClass = this.getThreatClass(report.threat);

    const threatBadgeColor =
      report.threat === 'safe'
        ? '#00FF88'
        : report.threat === 'suspicious'
        ? '#FFC107'
        : '#FF4D4D';
    const threatBgColor =
      report.threat === 'safe'
        ? 'rgba(0, 255, 136, 0.15)'
        : report.threat === 'suspicious'
        ? 'rgba(255, 193, 7, 0.15)'
        : 'rgba(255, 77, 77, 0.15)';

    const threatIcon =
      report.threat === 'safe'
        ? '✓'
        : report.threat === 'suspicious'
        ? '⚠'
        : '✕';

    const classificationReason = this.getClassificationReason(report.threat);

    const indicatorsArr = report.indicators || [];
    const issuesArr = report.issues || [];

    // Use threat-based colors for indicator list backgrounds and borders
    const bgColor = threatBgColor;
    const borderColor = threatBadgeColor;

    const indicatorsList = indicatorsArr.length > 0
      ? indicatorsArr.map((indicator) => `
        <li style="padding: 0.75rem; background: ${bgColor}; border-left: 4px solid ${borderColor}; border-radius: var(--radius-sm); margin-bottom: 0.75rem; word-wrap: break-word; overflow-wrap: break-word; max-width: 100%; box-sizing: border-box;">
          <strong style="color: #ffffff; display: block; word-wrap: break-word; overflow-wrap: break-word;">${this.escapeHtml(indicator)}</strong>
        </li>
      `).join('')
      : '<li style="color: #9CA3AF; padding: 0.5rem 0;">No indicators detected</li>';

    const issuesList = issuesArr.length > 0
      ? issuesArr.map(issue => `
      <li style="padding: 0.75rem; background: ${bgColor}; border-left: 4px solid ${borderColor}; border-radius: var(--radius-sm); margin-bottom: 0.75rem; word-wrap: break-word; overflow-wrap: break-word; max-width: 100%; box-sizing: border-box;">
        <strong style="color: #ffffff; display: block; word-wrap: break-word; overflow-wrap: break-word;">${this.escapeHtml(issue)}</strong>
      </li>
    `).join('')
      : '<li style="color: #9CA3AF; padding: 0.5rem 0;">No issues detected</li>';

    const card = document.createElement('div');
    card.className = 'modal-report-card';

    // TRACE: entering card creation
    try { console.log('[ReportsManager][TRACE] createDetailedModalReportCard start', { index, reportId: report && (report.id || report._id || '(no-id)') }); } catch (e) {}

    // Determine the display target (URL or sender email). For email types, NEVER show the full email body — only sender or extracted address.
    const isEmailType = String(report.type || '').toLowerCase().indexOf('email') !== -1;
    const _extractEmail = (text) => {
      if (!text) return '';
      try {
        const s = String(text);
        const m = s.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i);
        if (m) return m[0];
        const m2 = s.match(/([A-Z0-9._%+-]+)\s*@\s*([A-Z0-9.-]+)\s*\.\s*([A-Z]{2,})/i);
        if (m2) return (m2[1] + '@' + m2[2] + '.' + m2[3]).replace(/\s+/g, '');
        return '';
      } catch (e) { return ''; }
    };

    let target = '';

    const isValidEmail = (em) => {
      if (!em || typeof em !== 'string') return false;
      return /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i.test(em.trim());
    };

    if (isEmailType) {
      // Prefer a clean extracted email from senderEmail (handles "Name <email>")
      const extractedFromSender = _extractEmail(report.senderEmail) || '';
      const candidateSender = isValidEmail(extractedFromSender) ? extractedFromSender.trim() : '';
      const extractedFromValue = _extractEmail(report.value) || '';
      const candidateExtract = isValidEmail(extractedFromValue) ? extractedFromValue : '';
      
      // If we found an email, use it
      if (candidateSender || candidateExtract) {
        target = candidateSender || candidateExtract;
      } else {
        // No email found - show hint from first line
        const firstLine = String(report.value || '').split(/[\r\n]+/).filter(l => l.trim().length > 0)[0]?.trim() || '';
        if (firstLine && firstLine.length > 0) {
          target = `Unknown User - "${firstLine.substring(0, 60)}${firstLine.length > 60 ? '...' : ''}"`;
        } else {
          target = 'Unknown User';
        }
      }
    } else {
      // For non-email types prefer getDisplayTarget but ensure it doesn't include long bodies
      const display = this.getDisplayTarget ? String(this.getDisplayTarget(report) || '') : String(report.value || report.url || '');
      // If display looks like a long body (contains multiple spaces/newlines and no @), truncate it
      if (!display.includes('@') && (display.length > 200 || display.split(/\s+/).length > 20)) {
        target = display.substring(0, 100) + '...';
      } else {
        target = display;
      }
    }

    // DEBUG: Log minimal report info to trace filtered-modal leaks (temporary)
    try {
      const safeKeys = Object.keys(report || {}).slice(0, 10);
      const rid = report && (report.id || report._id || report.id === 0 ? (report.id || report._id) : '(no-id)');
      console.log('[ReportsManager][TRACE] modal card', { reportId: rid, keys: safeKeys, isEmailType: !!isEmailType, computedTarget: target ? String(target).slice(0, 200) : '(empty)', valueLength: report && report.value ? String(report.value).length : 0 });
    } catch (e) {
      console.log('[ReportsManager][TRACE] modal card logging failed');
    }

    card.innerHTML = `
      <div style="display:flex; flex-direction:column; gap:16px; width:100%; box-sizing:border-box; max-width:100%; overflow:hidden;">

        <!-- Header row with badge on left, then type and target -->
        <div style="display:flex; flex-wrap:wrap; gap:12px; align-items:flex-start;">
          <!-- Threat badge on the left -->
          <div style="display:flex; flex-direction:column; align-items:flex-start; gap:8px; flex-shrink:0;">
            <div style="padding:4px 10px; display:inline-flex; align-items:center; justify-content:center; border-radius:4px; background:${threatBgColor}; color:${threatBadgeColor}; font-weight:700; font-size:0.85rem;">${(report.threat||'').toUpperCase()}</div>
          </div>
          
          <!-- Type and target info -->
          <div style="flex:1; min-width:200px;">
            <div style="font-size:12px; color:var(--text-muted); text-transform:uppercase; margin-bottom:4px;">${report.type} Scan</div>
            <div style="font-family: 'Inter', monospace; font-size:13px; color:white; word-break:break-all; overflow-wrap:break-word;">${this.escapeHtml(target)}</div>
          </div>
        </div>

        <!-- Responsive grid for metadata, classification, summary, and indicators -->
        <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(250px, 1fr)); gap:16px; width:100%; box-sizing:border-box;">

          <!-- Meta column -->
          <div style="padding:12px; background: rgba(255,255,255,0.02); border-radius:8px; box-sizing:border-box;">
            <div style="font-size:12px; color:var(--text-muted);">Scan Date</div>
            <div style="font-weight:700;">${report.date}</div>
            <div style="height:8px"></div>
            <div style="font-size:12px; color:var(--text-muted);">Time</div>
            <div style="font-weight:700;">${report.time}</div>
            <div style="height:8px"></div>
            <div style="font-size:12px; color:var(--text-muted);">Confidence</div>
            <div style="font-weight:700;">${report.confidence}%</div>
            <div style="height:8px"></div>
            <div style="font-size:12px; color:var(--text-muted);">Risk Level</div>
            <div style="font-weight:700; color:${threatColor};">${this.formatRisk(report.riskLevel) || 'Unknown'}</div>
          </div>

          <!-- Classification column -->
          <div style="background: rgba(0,0,0,0.04); padding:16px; border-radius:8px; box-sizing:border-box;">
            <div style="font-size:13px; font-weight:800; margin-bottom:8px;">Classification Reason</div>
            <div style="color:var(--text-muted); line-height:1.5; word-wrap:break-word; overflow-wrap:break-word;">${classificationReason}</div>
          </div>

          <!-- Summary column -->
          <div style="background: rgba(0,0,0,0.04); padding:16px; border-radius:8px; box-sizing:border-box;">
            <div style="font-size:13px; font-weight:800; margin-bottom:8px;">Summary</div>
            <div style="color:var(--text-muted); line-height:1.5; word-wrap:break-word; overflow-wrap:break-word;">${this.escapeHtml(report.summary || '')}</div>
          </div>

        </div>

        <!-- Indicators and Issues in separate row -->
        <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(250px, 1fr)); gap:16px; width:100%; box-sizing:border-box;">
          
          <div style="background: rgba(255,255,255,0.02); padding:12px; border-radius:8px; box-sizing:border-box;">
            <div style="font-size:13px; font-weight:800; margin-bottom:8px;">Threat Indicators</div>
            <ul style="list-style:none; margin:0; padding:0; width:100%; box-sizing:border-box;">
              ${indicatorsList}
            </ul>
          </div>

          <div style="background: rgba(255,255,255,0.02); padding:12px; border-radius:8px; box-sizing:border-box;">
            <div style="font-size:13px; font-weight:800; margin-bottom:8px;">Detected Issues</div>
            <ul style="list-style:none; margin:0; padding:0; width:100%; box-sizing:border-box;">
              ${issuesList}
            </ul>
          </div>
          
        </div>

      </div>
    `;

    return card;
  }

  getClassificationReason(threat) {
    switch (threat) {
      case 'safe':
        return `This website has been verified as safe and legitimate. It contains valid security certificates, recognized domain registration, proper server configuration, and no identified malware or phishing signatures. You can safely visit this website.`;

      case 'suspicious':
        return `This website exhibits suspicious characteristics that warrant caution. Indicators include unusual domain registration patterns, recent domain registration, suspicious redirects, or other anomalies that suggest it may be attempting to impersonate a legitimate service. We recommend verifying the website identity before entering personal information.`;

      case 'malicious':
        return `This website has been identified as malicious and presents a serious security threat. It has been flagged for phishing attempts, malware distribution, credential harvesting, or other malicious activities. We strongly recommend avoiding this website entirely and reporting it to the appropriate authorities.`;

      default:
        return 'Classification information is not available.';
    }
  }

  async generateAndDownloadPDF(filename, displayText) {
    try {
      await waitForLibraries();

      const { jsPDF } = window.jspdf;
      this.showNotification('Generating PDF...', 'info');

      // Allow UI to update notification
      await new Promise(r => setTimeout(r, 50));

      const pageWidth = 210; // mm - standard width
      const margin = 15;
      const usableWidth = pageWidth - (margin * 2);

      let pdf = null;

      // Process each report on its own custom-sized page
      for (let i = 0; i < this.filteredReports.length; i++) {
        const report = this.filteredReports[i];
        
        // Calculate height needed for THIS specific report
        let reportHeight = 90; // Header + base structure
        
        // Add target height (truncated to max 90 chars)
        const targetText = String(this.getDisplayTarget ? this.getDisplayTarget(report) : (report.senderEmail || report.value || report.url || 'N/A'));
        const truncatedTargetText = targetText.length > 90 ? targetText.substring(0, 90) + '...' : targetText;
        const targetLineCount = Math.ceil(truncatedTargetText.length / 80);
        reportHeight += 15 + (targetLineCount * 5);
        
        // Add metadata section
        reportHeight += 22;
        
        // Add classification reason
        const classificationText = this.getClassificationReason(report.threat || '');
        const classificationLineCount = Math.ceil(classificationText.length / 100);
        reportHeight += 16 + (classificationLineCount * 5);
        
        // Add summary if exists
        if (report.summary) {
          const summaryLineCount = Math.ceil(String(report.summary).length / 100);
          reportHeight += 16 + (summaryLineCount * 5);
        }
        
        // Add indicators if exist
        if (report.indicators && report.indicators.length > 0) {
          reportHeight += 16;
          report.indicators.forEach(ind => {
            const indicatorLineCount = Math.ceil(String(ind).length / 90);
            reportHeight += (indicatorLineCount * 5) + 2;
          });
        }
        
        // Add issues if exist
        if (report.issues && report.issues.length > 0) {
          reportHeight += 16;
          report.issues.forEach(issue => {
            const issueLineCount = Math.ceil(String(issue).length / 90);
            reportHeight += (issueLineCount * 5) + 2;
          });
        }
        
        reportHeight += 20; // Footer space
        reportHeight = Math.max(reportHeight, 150); // Minimum height

        // Create new PDF or add new page with custom height for this report
        if (i === 0) {
          pdf = new jsPDF({ 
            unit: 'mm', 
            format: [pageWidth, reportHeight],
            compress: true 
          });
        } else {
          pdf.addPage([pageWidth, reportHeight], 'portrait');
        }

        let cursorY = margin;

        // ===== PROFESSIONAL HEADER =====
        pdf.setFillColor(11, 99, 217); // PhishNet blue
        pdf.rect(0, 0, pageWidth, 35, 'F');
        
        pdf.setTextColor(255, 255, 255);
        pdf.setFontSize(24);
        pdf.setFont('Helvetica', 'bold');
        pdf.text('PhishNet Security Report', margin, 15);
        
        pdf.setFontSize(11);
        pdf.setFont('Helvetica', 'normal');
        pdf.text(displayText, margin, 23);
        
        const dateStr = new Date().toLocaleDateString('en-US', { 
          year: 'numeric', month: 'long', day: 'numeric', hour: '2-digit', minute: '2-digit' 
        });
        pdf.text(`Generated: ${dateStr}`, margin, 29);

        cursorY = 45;

        // ===== INDIVIDUAL REPORT =====
        const cardStartY = cursorY;

        // Threat color coding
        let statusColor, statusBg, statusText;
        if (report.threat === 'safe') {
          statusColor = [16, 185, 129]; // Green text #10B981
          statusBg = [209, 250, 229]; // Light mint background #D1FAE5
          statusText = 'SAFE';
        } else if (report.threat === 'suspicious') {
          statusColor = [255, 193, 7];
          statusBg = [254, 252, 232];
          statusText = 'SUSPICIOUS';
        } else {
          statusColor = [239, 68, 68];
          statusBg = [254, 226, 226];
          statusText = 'MALICIOUS';
        }

        // Card background
        pdf.setFillColor(255, 255, 255);
        pdf.setDrawColor(226, 232, 240);

        cursorY += 8;

        // Status badge on the left - fit exactly to text width
        pdf.setFontSize(9);
        pdf.setFont('Helvetica', 'bold');
        const textWidth = pdf.getTextWidth(statusText);
        const badgePadding = 2; // Minimal padding on each side
        const badgeWidth = textWidth + (badgePadding * 2);
        const badgeHeight = 5.5;
        
        pdf.setFillColor(...statusBg);
        pdf.roundedRect(margin + 5, cursorY - 3.5, badgeWidth, badgeHeight, 1, 1, 'F');
        pdf.setTextColor(...statusColor);
        pdf.text(statusText, margin + 5 + badgePadding, cursorY);

        cursorY += 8;

        // Scan type label
        pdf.setTextColor(100, 116, 139);
        pdf.setFontSize(8);
        pdf.setFont('Helvetica', 'bold');
        pdf.text(`${(report.type || 'URL').toUpperCase()} SCAN`, margin + 5, cursorY);
        
        // Report number indicator
        pdf.setTextColor(100, 116, 139);
        pdf.setFontSize(9);
        pdf.text(`Report ${i + 1} of ${this.filteredReports.length}`, pageWidth - margin - 35, cursorY);

        cursorY += 5;

        // Scanned Target - truncate if too long
        const reportTarget = this.getDisplayTarget(report);
        const maxUrlLength = 90; // Maximum characters to display
        const truncatedTarget = reportTarget.length > maxUrlLength 
          ? reportTarget.substring(0, maxUrlLength) + '...' 
          : reportTarget;
        
        const reportTargetLines = pdf.splitTextToSize(truncatedTarget, usableWidth - 10);
        pdf.setTextColor(0, 0, 0); // Simple black color
        pdf.setFontSize(10);
        pdf.setFont('Helvetica', 'normal');
        pdf.text(reportTargetLines, margin + 5, cursorY);
        cursorY += reportTargetLines.length * 5;

        cursorY += 8;

        // Metadata grid
        const metaStartY = cursorY;
        const colWidth = usableWidth / 4;

        pdf.setFontSize(8);
        pdf.setFont('Helvetica', 'bold');
        pdf.setTextColor(100, 116, 139);
        
        // Column 1: Date
        pdf.text('DATE', margin + 8, cursorY);
        pdf.setFont('Helvetica', 'normal');
        pdf.setTextColor(15, 23, 42);
        pdf.setFontSize(9);
        pdf.text(report.date || 'N/A', margin + 8, cursorY + 5);

        // Column 2: Time
        pdf.setFont('Helvetica', 'bold');
        pdf.setTextColor(100, 116, 139);
        pdf.setFontSize(8);
        pdf.text('TIME', margin + 8 + colWidth, cursorY);
        pdf.setFont('Helvetica', 'normal');
        pdf.setTextColor(15, 23, 42);
        pdf.setFontSize(9);
        pdf.text(report.time || 'N/A', margin + 8 + colWidth, cursorY + 5);

        // Column 3: Confidence
        pdf.setFont('Helvetica', 'bold');
        pdf.setTextColor(100, 116, 139);
        pdf.setFontSize(8);
        pdf.text('CONFIDENCE', margin + 8 + colWidth * 2, cursorY);
        pdf.setFont('Helvetica', 'normal');
        pdf.setTextColor(15, 23, 42);
        pdf.setFontSize(9);
        pdf.text(`${report.confidence || 0}%`, margin + 8 + colWidth * 2, cursorY + 5);

        // Column 4: Risk
        pdf.setFont('Helvetica', 'bold');
        pdf.setTextColor(100, 116, 139);
        pdf.setFontSize(8);
        pdf.text('RISK LEVEL', margin + 8 + colWidth * 3, cursorY);
        pdf.setFont('Helvetica', 'normal');
        pdf.setTextColor(...statusColor);
        pdf.setFontSize(9);
        pdf.text(this.formatRisk(report.riskLevel) || 'Unknown', margin + 8 + colWidth * 3, cursorY + 5);

        cursorY += 14;

        // Divider line
        pdf.setDrawColor(226, 232, 240);
        pdf.setLineWidth(0.3);
        pdf.line(margin + 5, cursorY, margin + usableWidth - 5, cursorY);
        cursorY += 8;

        // Classification Reason
        pdf.setFontSize(10);
        pdf.setFont('Helvetica', 'bold');
        pdf.setTextColor(11, 99, 217);
        pdf.text('Classification Reason', margin + 8, cursorY);
        cursorY += 6;

        const reportClassReason = this.getClassificationReason(report.threat || '');
        const reportClassLines = pdf.splitTextToSize(reportClassReason, usableWidth - 16);
        pdf.setFont('Helvetica', 'normal');
        pdf.setTextColor(51, 65, 85);
        pdf.setFontSize(9);
        pdf.text(reportClassLines, margin + 8, cursorY);
        cursorY += reportClassLines.length * 5 + 8;

        // Summary
        if (report.summary) {
          pdf.setFontSize(10);
          pdf.setFont('Helvetica', 'bold');
          pdf.setTextColor(11, 99, 217);
          pdf.text('Summary', margin + 8, cursorY);
          cursorY += 6;

          const sumLines = pdf.splitTextToSize(String(report.summary), usableWidth - 16);
          pdf.setFont('Helvetica', 'normal');
          pdf.setTextColor(51, 65, 85);
          pdf.setFontSize(9);
          pdf.text(sumLines, margin + 8, cursorY);
          cursorY += sumLines.length * 5 + 8;
        }

        // Threat Indicators or Security Features (based on threat level)
        if (report.indicators && report.indicators.length > 0) {
          pdf.setFontSize(10);
          pdf.setFont('Helvetica', 'bold');
          
          if (report.threat === 'safe') {
            // For SAFE reports - show as Security Features with green color
            pdf.setTextColor(16, 185, 129);
            
            // Draw checkmark icon
            pdf.setLineWidth(0.6);
            pdf.setDrawColor(16, 185, 129);
            const iconX = margin + 8;
            const iconY = cursorY - 3;
            // Checkmark
            pdf.line(iconX, iconY + 1.5, iconX + 1, iconY + 2.5);
            pdf.line(iconX + 1, iconY + 2.5, iconX + 3, iconY);
            
            pdf.setFontSize(10);
            pdf.text('Security Features Detected', margin + 14, cursorY);
            cursorY += 6;

            pdf.setFont('Helvetica', 'normal');
            pdf.setTextColor(51, 65, 85);
            pdf.setFontSize(9);

            for (const ind of report.indicators) {
              // Draw green bullet point
              pdf.setFillColor(16, 185, 129);
              pdf.circle(margin + 11, cursorY - 1.5, 0.8, 'F');
              
              let cleanInd = String(ind)
                .replace(/^[^a-zA-Z0-9]+/g, '')
                .trim();
              
              const indLines = pdf.splitTextToSize(cleanInd, usableWidth - 20);
              pdf.text(indLines, margin + 14, cursorY);
              cursorY += indLines.length * 5 + 2;
            }
          } else {
            // For SUSPICIOUS/MALICIOUS reports - show as Threat Indicators with red color
            pdf.setTextColor(239, 68, 68);
            
            // Draw warning triangle icon
            pdf.setLineWidth(0.5);
            pdf.setDrawColor(239, 68, 68);
            const iconX = margin + 8;
            const iconY = cursorY - 3;
            // Triangle
            pdf.line(iconX, iconY + 3, iconX + 1.5, iconY);
            pdf.line(iconX + 1.5, iconY, iconX + 3, iconY + 3);
            pdf.line(iconX + 3, iconY + 3, iconX, iconY + 3);
            // Exclamation mark
            pdf.setFontSize(7);
            pdf.text('!', iconX + 1.2, iconY + 2.5);
            
            pdf.setFontSize(10);
            pdf.text('Threat Indicators', margin + 14, cursorY);
            cursorY += 6;

            pdf.setFont('Helvetica', 'normal');
            pdf.setTextColor(51, 65, 85);
            pdf.setFontSize(9);

            for (const ind of report.indicators) {
              // Draw red bullet point
              pdf.setFillColor(239, 68, 68);
              pdf.circle(margin + 11, cursorY - 1.5, 0.8, 'F');
              
              let cleanInd = String(ind)
                .replace(/^[^a-zA-Z0-9]+/g, '')
                .trim();
              
              const indLines = pdf.splitTextToSize(cleanInd, usableWidth - 20);
              pdf.text(indLines, margin + 14, cursorY);
              cursorY += indLines.length * 5 + 2;
            }
          }
          cursorY += 4;
        }

        // Detected Issues (only show for suspicious/malicious reports)
        if (report.issues && report.issues.length > 0 && report.threat !== 'safe') {
          pdf.setFontSize(10);
          pdf.setFont('Helvetica', 'bold');
          pdf.setTextColor(239, 68, 68);
          
          // Draw X icon
          pdf.setLineWidth(0.6);
          pdf.setDrawColor(239, 68, 68);
          const xIconX = margin + 8;
          const xIconY = cursorY - 3;
          pdf.line(xIconX, xIconY, xIconX + 3, xIconY + 3);
          pdf.line(xIconX + 3, xIconY, xIconX, xIconY + 3);
          
          pdf.setFontSize(10);
          pdf.text('Detected Issues', margin + 14, cursorY);
          cursorY += 6;

          pdf.setFont('Helvetica', 'normal');
          pdf.setTextColor(51, 65, 85);
          pdf.setFontSize(9);

          for (const issue of report.issues) {
            // Draw bullet point
            pdf.setFillColor(239, 68, 68);
            pdf.circle(margin + 11, cursorY - 1.5, 0.8, 'F');
            
            // Clean the issue text - remove ALL leading non-letter characters
            let cleanIssue = String(issue)
              .replace(/^[^a-zA-Z0-9]+/g, '')  // Remove all leading non-alphanumeric chars
              .trim();
            
            const issueLines = pdf.splitTextToSize(cleanIssue, usableWidth - 20);
            pdf.text(issueLines, margin + 14, cursorY);
            cursorY += issueLines.length * 5 + 2;
          }
          cursorY += 4;
        }

        cursorY += 5;

        // Draw final card border
        const cardHeight = cursorY - cardStartY;
        pdf.setDrawColor(226, 232, 240);
        pdf.roundedRect(margin, cardStartY, usableWidth, cardHeight, 2, 2, 'D');
      }

      // Save PDF
      pdf.save(filename);
      this.showNotification('PDF downloaded successfully!', 'success');

      // PDF already saved in the FAST_MODE or fallback flow above.

    } catch (error) {
      console.error('PDF generation error:', error);
      this.showNotification('Failed to generate PDF', 'error');
    }
  }

  updateModalStatistics() {
    let safeCount = 0;
    let suspiciousCount = 0;
    let maliciousCount = 0;

    this.filteredReports.forEach((report) => {
      if (report.threat === 'safe') safeCount++;
      else if (report.threat === 'suspicious') suspiciousCount++;
      else if (report.threat === 'malicious') maliciousCount++;
    });

    document.getElementById('modal-stat-total').textContent = this.filteredReports.length;
    document.getElementById('modal-stat-safe').textContent = safeCount;
    document.getElementById('modal-stat-suspicious').textContent = suspiciousCount;
    document.getElementById('modal-stat-malicious').textContent = maliciousCount;
  }

  openModal() {
    const modal = document.getElementById('filtered-reports-modal');
    if (modal) {
      modal.classList.remove('hidden');
      document.body.style.overflow = 'hidden';
    }
  }

  closeModal() {
    const modal = document.getElementById('filtered-reports-modal');
    if (modal) {
      modal.classList.add('hidden');
      document.body.style.overflow = '';
    }
  }

  downloadFilteredReportsPDF() {
    if (!this.filteredReports || this.filteredReports.length === 0) {
      this.showNotification('No reports to download', 'error');
      return;
    }

    const { displayText } = this.getDateRange(this.currentFilter);
    const date = new Date();
    const filename = `PhishNet_Filtered_Reports_${displayText.replace(/\s+/g, '_')}_${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')}.pdf`;
    
    // Create a print-friendly container with all reports visible
    this.generateAndDownloadPDF(filename, displayText);
  }

  generateFilteredReportsPDF(periodText) {
    const { displayText } = this.getDateRange(this.currentFilter);

    let safeCount = 0;
    let suspiciousCount = 0;
    let maliciousCount = 0;

    const reportsHtml = this.filteredReports
      .map((report) => {
        if (report.threat === 'safe') safeCount++;
        else if (report.threat === 'suspicious') suspiciousCount++;
        else if (report.threat === 'malicious') maliciousCount++;

        const threatColor =
          report.threat === 'safe'
            ? '#00FF88'
            : report.threat === 'suspicious'
            ? '#FFC107'
            : '#FF4D4D';

        const indicatorsHtml = report.indicators
          .map(
            (indicator) =>
              `<li style="margin-bottom: 8px; padding: 8px; background: rgba(11, 99, 217, 0.1); border-left: 3px solid #0B63D9; border-radius: 4px;">
                <strong>${this.escapeHtml(indicator)}</strong>
              </li>`
          )
          .join('');

        const issuesHtml = report.issues
          .map((issue) => `<li style="margin-bottom: 8px; color: #333;">${this.escapeHtml(issue)}</li>`)
          .join('');

        return `
          <div style="page-break-inside: avoid; margin-bottom: 30px; border: 1px solid #ddd; padding: 20px; border-radius: 8px;">
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 15px; margin-bottom: 15px;">
              <div>
                <p style="font-size: 12px; color: #999; margin: 0 0 5px 0; text-transform: uppercase;">Scan Type</p>
                <p style="font-weight: 600; color: #333; margin: 0;">${report.type === 'url' ? 'URL Scan' : 'Email Scan'}</p>
              </div>
              <div>
                <p style="font-size: 12px; color: #999; margin: 0 0 5px 0; text-transform: uppercase;">Threat Assessment</p>
                <p style="font-weight: 600; color: ${threatColor}; margin: 0;">${report.threat.toUpperCase()}</p>
              </div>
              <div>
                <p style="font-size: 12px; color: #999; margin: 0 0 5px 0; text-transform: uppercase;">Date & Time</p>
                <p style="font-weight: 600; color: #333; margin: 0;">${report.date} at ${report.time}</p>
              </div>
              <div>
                <p style="font-size: 12px; color: #999; margin: 0 0 5px 0; text-transform: uppercase;">Confidence Score</p>
                <p style="font-weight: 600; color: #333; margin: 0;">${report.confidence}%</p>
              </div>
            </div>

            <div style="margin-bottom: 15px;">
              <p style="font-size: 12px; color: #999; margin: 0 0 8px 0; text-transform: uppercase; font-weight: 600;">Target</p>
              <p style="font-weight: 600; color: #333; margin: 0; word-break: break-all; font-family: monospace; font-size: 12px; background: #f0f0f0; padding: 8px; border-radius: 4px;">${this.escapeHtml(this.getDisplayTarget(report))}</p>
            </div>

            <div style="margin-bottom: 15px; padding: 12px; background: #f0f7ff; border-left: 4px solid #0B63D9; border-radius: 4px;">
              <p style="font-size: 12px; color: #0B63D9; margin: 0 0 8px 0; text-transform: uppercase; font-weight: 600;">Classification Reason</p>
              <p style="color: #333; margin: 0; line-height: 1.5; font-size: 13px;">${this.getClassificationReason(report.threat)}</p>
            </div>

            <div style="margin-bottom: 15px;">
              <p style="font-size: 12px; color: #999; margin: 0 0 8px 0; text-transform: uppercase; font-weight: 600;">Summary</p>
              <p style="color: #333; margin: 0; line-height: 1.5; font-size: 13px;">${this.escapeHtml(report.summary)}</p>
            </div>

            ${report.indicators.length > 0 ? `<h4 style="margin: 15px 0 10px 0; color: #0B63D9; font-size: 13px; font-weight: 600; text-transform: uppercase;">Threat Indicators</h4><ul style="list-style: none; padding: 0; margin: 0;">${indicatorsHtml}</ul>` : ''}

            ${report.issues.length > 0 ? `<h4 style="margin: 15px 0 10px 0; color: #0B63D9; font-size: 13px; font-weight: 600; text-transform: uppercase;">Detected Issues</h4><ul style="list-style: disc; padding-left: 20px; margin: 0;">${issuesHtml}</ul>` : ''}
          </div>
        `;
      })
      .join('');

    return `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>PhishNet Filtered Reports</title>
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
      border-bottom: 3px solid #0B63D9;
      padding-bottom: 20px;
    }
    .logo { font-size: 28px; font-weight: 700; color: #0B63D9; margin-bottom: 10px; }
    h1 { font-size: 24px; color: #333; margin-bottom: 10px; }
    .period-info { font-size: 14px; color: #666; margin: 15px 0; }
    .summary-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin: 20px 0; }
    .summary-box { padding: 15px; background: #f9f9f9; border-left: 4px solid #0B63D9; border-radius: 4px; text-align: center; }
    .summary-label { font-size: 11px; color: #666; margin-bottom: 8px; text-transform: uppercase; font-weight: 600; }
    .summary-value { font-size: 24px; font-weight: 700; color: #0B63D9; }
    h2 { margin: 30px 0 20px 0; color: #333; border-bottom: 2px solid #0B63D9; padding-bottom: 10px; font-size: 18px; }
    @media print { body { background: white; padding: 0; } .container { box-shadow: none; } }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="logo">PhishNet</div>
      <h1>Security Scan Reports</h1>
      <p class="period-info">Time Period: <strong>${displayText}</strong></p>
      <p class="period-info" style="font-size: 12px;">Generated: ${new Date().toLocaleString()}</p>
    </div>

    <div class="summary-grid">
      <div class="summary-box">
        <div class="summary-label">Total Reports</div>
        <div class="summary-value">${this.filteredReports.length}</div>
      </div>
      <div class="summary-box">
        <div class="summary-label">Safe</div>
        <div class="summary-value" style="color: #00FF88;">${safeCount}</div>
      </div>
      <div class="summary-box">
        <div class="summary-label">Suspicious</div>
        <div class="summary-value" style="color: #FFC107;">${suspiciousCount}</div>
      </div>
      <div class="summary-box">
        <div class="summary-label">Malicious</div>
        <div class="summary-value" style="color: #FF4D4D;">${maliciousCount}</div>
      </div>
    </div>

    <h2>Detailed Reports</h2>
    ${reportsHtml}

    <div style="text-align: center; margin-top: 40px; padding-top: 20px; border-top: 1px solid #eee; color: #999; font-size: 12px;">
      <p>PhishNet Security Report | Confidential and Intended for Authorized Use Only</p>
    </div>
  </div>
</body>
</html>`;
  }
}


// Add CSS animations
const style = document.createElement('style');
style.textContent = `
  @keyframes slideIn {
    from { transform: translateX(400px); opacity: 0; }
    to { transform: translateX(0); opacity: 1; }
  }
  @keyframes slideOut {
    from { transform: translateX(0); opacity: 1; }
    to { transform: translateX(400px); opacity: 0; }
  }
`;
document.head.appendChild(style);

// Helper function to wait for libraries to load
function waitForLibraries() {
  return new Promise((resolve) => {
    const checkLibraries = () => {
      // jsPDF is required for fast text-based PDF generation; html2canvas is optional (fallback)
      if (typeof window !== 'undefined' && typeof window.jspdf !== 'undefined') {
        resolve(true);
      } else {
        setTimeout(checkLibraries, 100);
      }
    };
    checkLibraries();
  });
}

// PDF Download Function
async function downloadReportAsPDF(elementId, fileName = "report.pdf") {
  try {
    await waitForLibraries();
    if (document.fonts && document.fonts.ready) await document.fonts.ready;

    const { jsPDF } = window.jspdf;

    // If exporting the single main report and we have a currentReport, create a professional text-based PDF
    if (window.reportsManager && window.reportsManager.currentReport && elementId === 'main-report') {
      const report = window.reportsManager.currentReport;
      
      if (window.reportsManager) window.reportsManager.showNotification('Generating PDF...', 'info');
      
      const pdf = new jsPDF('p', 'mm', 'a4');
      const pageWidth = pdf.internal.pageSize.getWidth();
      const pageHeight = pdf.internal.pageSize.getHeight();
      const margin = 20;
      const contentWidth = pageWidth - margin * 2;
      let y = margin;
      
      // Helper: add new page if needed
      const checkNewPage = (requiredHeight = 20) => {
        if (y + requiredHeight > pageHeight - 20) {
          pdf.addPage();
          y = margin;
          return true;
        }
        return false;
      };
      
      // Ultra-minimal color palette (matching Replit design)
      const black = [0, 0, 0];
      const muted = [115, 115, 115];
      const lightMuted = [160, 160, 160];
      const borderClr = [230, 230, 230];
      const mutedBg = [245, 245, 245];
      const safeGreen = [22, 163, 74];
      const dangerRed = [220, 38, 38];
      const warnOrange = [234, 179, 8];
      
      const threat = (report.threat || 'safe').toLowerCase();
      const statusColor = threat === 'safe' ? safeGreen : threat === 'suspicious' ? warnOrange : dangerRed;
      
      // Parse URL for target specification
      let urlHost = '', urlDomain = '', urlProtocol = '', hasSsl = false;
      try {
        const u = new URL(report.value);
        urlHost = u.hostname;
        urlDomain = report.domain || urlHost.replace(/^www\./, '');
        urlProtocol = u.protocol === 'https:' ? 'TLS 1.3' : 'HTTP';
        hasSsl = u.protocol === 'https:';
      } catch (e) {
        urlHost = report.domain || report.value || 'N/A';
        urlDomain = report.domain || 'N/A';
        urlProtocol = (report.value || '').startsWith('https') ? 'TLS 1.3' : 'HTTP';
        hasSsl = (report.value || '').startsWith('https');
      }
      
      // Helper: spaced uppercase text (simulates letter-spacing)
      const spacedText = (text, spacing = 0.6) => {
        return text.split('').join(String.fromCharCode(8202).repeat(Math.round(spacing)));
      };
      
      // ===== HEADER — Ultra Minimal =====
      // Black dot
      pdf.setFillColor(...black);
      pdf.circle(margin + 1, y + 1, 0.8, 'F');
      
      // "PHISHNET INTELLIGENCE" uppercase tracked
      pdf.setTextColor(...muted);
      pdf.setFontSize(6.5);
      pdf.setFont('helvetica', 'bold');
      pdf.text(spacedText('PHISHNET INTELLIGENCE'), margin + 4, y + 1.8);
      
      // "Scan Report" large title
      y += 10;
      pdf.setTextColor(...black);
      pdf.setFontSize(26);
      pdf.setFont('helvetica', 'normal');
      pdf.text('Scan ', margin, y);
      const scanW = pdf.getTextWidth('Scan ');
      pdf.setFont('helvetica', 'bold');
      pdf.text('Report', margin + scanW, y);
      
      // Right side: Date + ID (mono font, right-aligned)
      const rightX = pageWidth - margin;
      pdf.setFont('courier', 'normal');
      pdf.setFontSize(7);
      
      // Date row
      pdf.setTextColor(...muted);
      pdf.text('DATE', rightX - 52, y - 9);
      pdf.setTextColor(...black);
      pdf.text(report.date || 'N/A', rightX, y - 9, { align: 'right' });
      
      // Separator line
      pdf.setDrawColor(...borderClr);
      pdf.setLineWidth(0.15);
      pdf.line(rightX - 52, y - 6, rightX, y - 6);
      
      // ID row
      pdf.setTextColor(...muted);
      pdf.text('ID', rightX - 52, y - 2.5);
      const idStr = report.id ? String(report.id).substring(0, 8).toUpperCase() + '...' : 'N/A';
      pdf.setTextColor(...black);
      pdf.text(idStr, rightX, y - 2.5, { align: 'right' });
      
      y += 22;
      
      // ===== HERO RESULT — Giant Status Text =====
      const heroWord = threat === 'safe' ? 'Safe.' : threat === 'suspicious' ? 'Suspicious.' : 'Malicious.';
      pdf.setTextColor(...black);
      pdf.setFontSize(64);
      pdf.setFont('helvetica', 'bold');
      pdf.text(heroWord, margin, y);
      
      // Badge + description (offset right of hero)
      const heroW = pdf.getTextWidth(heroWord);
      const badgeX = Math.min(margin + heroW + 8, margin + 105);
      const badgeY = y - 16;
      
      // Colored badge text
      pdf.setTextColor(...statusColor);
      pdf.setFontSize(6.5);
      pdf.setFont('helvetica', 'bold');
      const badgeSymbol = threat === 'safe' ? 'VERIFIED TARGET' : threat === 'suspicious' ? 'SUSPICIOUS TARGET' : 'THREAT DETECTED';
      pdf.text(spacedText(badgeSymbol), badgeX, badgeY);
      
      // Description
      pdf.setTextColor(...muted);
      pdf.setFontSize(8);
      pdf.setFont('helvetica', 'normal');
      const heroDesc = threat === 'safe'
        ? 'No malicious signatures or behavioral\nanomalies detected during deep analysis.'
        : threat === 'suspicious'
        ? 'Suspicious patterns detected during\nanalysis. Exercise caution.'
        : 'Malicious signatures or behavioral\nanomalies detected. Avoid this target.';
      heroDesc.split('\n').forEach((line, i) => {
        pdf.text(line, badgeX, badgeY + 5 + (i * 4));
      });
      
      y += 14;
      
      // ===== STATS GRID — Border-left accent =====
      const confidenceLabel = report.confidence >= 80 ? 'High' : report.confidence >= 50 ? 'Medium' : 'Low';
      const riskSub = threat === 'safe' ? 'Minimal' : threat === 'suspicious' ? 'Moderate' : 'Severe';
      
      const stats = [
        { label: 'CONFIDENCE', value: `${report.confidence || 0}%`, sub: confidenceLabel },
        { label: 'RISK LEVEL', value: report.riskLevel || 'Low', sub: riskSub },
        { label: 'THREAT SCORE', value: `${report.threatScore || 0}`, sub: 'Score' },
        { label: 'ENCRYPTION', value: hasSsl ? 'SSL' : 'None', sub: hasSsl ? 'Valid' : 'N/A' }
      ];
      
      const colW = contentWidth / 4;
      stats.forEach((stat, i) => {
        const sx = margin + (i * colW);
        
        // Left border accent line
        pdf.setDrawColor(...borderClr);
        pdf.setLineWidth(0.3);
        pdf.line(sx, y, sx, y + 16);
        
        // Label (tiny uppercase)
        pdf.setTextColor(...muted);
        pdf.setFontSize(5.5);
        pdf.setFont('helvetica', 'bold');
        pdf.text(spacedText(stat.label), sx + 4, y + 4);
        
        // Value (large)
        pdf.setTextColor(...black);
        pdf.setFontSize(15);
        pdf.setFont('helvetica', 'bold');
        pdf.text(stat.value, sx + 4, y + 12);
        
        // Sub text after value
        const vw = pdf.getTextWidth(stat.value);
        pdf.setTextColor(...muted);
        pdf.setFontSize(6.5);
        pdf.setFont('helvetica', 'normal');
        pdf.text(stat.sub, sx + 5 + vw, y + 12);
      });
      
      y += 30;
      
      // ===== TARGET SPECIFICATION =====
      checkNewPage(55);
      
      // Section header
      pdf.setTextColor(...lightMuted);
      pdf.setFontSize(7);
      pdf.setFont('helvetica', 'bold');
      pdf.text(spacedText('TARGET SPECIFICATION'), margin, y);
      y += 3;
      pdf.setDrawColor(...borderClr);
      pdf.setLineWidth(0.15);
      pdf.line(margin, y, pageWidth - margin, y);
      y += 10;
      
      // "ENDPOINT URL" label
      pdf.setTextColor(...muted);
      pdf.setFontSize(5.5);
      pdf.setFont('helvetica', 'bold');
      pdf.text(spacedText('ENDPOINT URL'), margin, y);
      y += 5;
      
      // URL box with muted background
      pdf.setFillColor(...mutedBg);
      pdf.roundedRect(margin, y - 3, contentWidth, 10, 1.5, 1.5, 'F');
      pdf.setTextColor(...black);
      pdf.setFontSize(9);
      pdf.setFont('courier', 'normal');
      const urlDisplay = String(report.value || 'N/A');
      const urlTrunc = urlDisplay.length > 72 ? urlDisplay.substring(0, 72) + '...' : urlDisplay;
      pdf.text(urlTrunc, margin + 4, y + 4);
      y += 16;
      
      // Domain / Host / Protocol / Certificate grid (2 columns)
      const halfW = contentWidth / 2 - 8;
      const gridData = [
        [
          { label: 'Domain', value: urlDomain || 'N/A' },
          { label: 'Host', value: urlHost || 'N/A' }
        ],
        [
          { label: 'Protocol', value: urlProtocol },
          { label: 'Certificate', value: hasSsl ? 'Active' : 'None', green: hasSsl }
        ]
      ];
      
      gridData.forEach((col, ci) => {
        const cx = margin + (ci * (halfW + 16));
        col.forEach((item, ri) => {
          const ry = y + (ri * 12);
          
          // Label
          pdf.setTextColor(...muted);
          pdf.setFontSize(9);
          pdf.setFont('helvetica', 'normal');
          pdf.text(item.label, cx, ry);
          
          // Value (right-aligned)
          pdf.setTextColor(...(item.green ? safeGreen : black));
          pdf.setFont('helvetica', 'bold');
          pdf.text(item.value, cx + halfW, ry, { align: 'right' });
          
          // Bottom border
          pdf.setDrawColor(...borderClr);
          pdf.setLineWidth(0.12);
          pdf.line(cx, ry + 3, cx + halfW, ry + 3);
        });
      });
      
      y += 32;
      
      // ===== SECURITY ASSESSMENT =====
      checkNewPage(55);
      
      // Section header
      pdf.setTextColor(...lightMuted);
      pdf.setFontSize(7);
      pdf.setFont('helvetica', 'bold');
      pdf.text(spacedText('SECURITY ASSESSMENT'), margin, y);
      y += 3;
      pdf.setDrawColor(...borderClr);
      pdf.setLineWidth(0.15);
      pdf.line(margin, y, pageWidth - margin, y);
      y += 10;
      
      // Left: summary prose
      const summaryText = report.summary || 'No summary available.';
      const summaryMaxW = contentWidth * 0.58;
      pdf.setTextColor(30, 30, 30);
      pdf.setFontSize(10.5);
      pdf.setFont('helvetica', 'normal');
      const sumLines = pdf.splitTextToSize(summaryText, summaryMaxW);
      const sumStartY = y;
      
      sumLines.forEach(line => {
        checkNewPage(6);
        pdf.text(line, margin, y);
        y += 5.5;
      });
      
      // Right: indicator status dots
      const dotX = margin + contentWidth * 0.64;
      let dotY = sumStartY;
      
      // Base indicators based on threat level
      let dotItems;
      if (threat === 'safe') {
        dotItems = [
          { label: 'Reputation: Clean', color: safeGreen },
          { label: 'Malware: None', color: safeGreen },
          { label: 'Phishing: Negative', color: safeGreen }
        ];
      } else if (threat === 'suspicious') {
        dotItems = [
          { label: 'Reputation: Suspicious', color: warnOrange },
          { label: 'Malware: Check Required', color: warnOrange },
          { label: 'Phishing: Possible', color: warnOrange }
        ];
      } else {
        dotItems = [
          { label: 'Reputation: Flagged', color: dangerRed },
          { label: 'Malware: Detected', color: dangerRed },
          { label: 'Phishing: Positive', color: dangerRed }
        ];
      }
      
      dotItems.forEach(item => {
        pdf.setFillColor(...item.color);
        pdf.circle(dotX, dotY + 0.7, 0.5, 'F');
        pdf.setTextColor(...black);
        pdf.setFontSize(8);
        pdf.setFont('helvetica', 'normal');
        pdf.text(item.label, dotX + 3, dotY + 1.5);
        dotY += 8;
      });
      
      y = Math.max(y, dotY) + 8;
      
      // ===== THREAT INDICATORS (if any) =====
      const indicators = report.indicators || [];
      if (indicators.length > 0) {
        checkNewPage(35);
        
        pdf.setTextColor(...lightMuted);
        pdf.setFontSize(7);
        pdf.setFont('helvetica', 'bold');
        pdf.text(spacedText('THREAT INDICATORS'), margin, y);
        y += 3;
        pdf.setDrawColor(...borderClr);
        pdf.setLineWidth(0.15);
        pdf.line(margin, y, pageWidth - margin, y);
        y += 8;
        
        indicators.forEach(indicator => {
          checkNewPage(10);
          
          // Colored dot
          pdf.setFillColor(...statusColor);
          pdf.circle(margin + 2, y + 0.7, 0.5, 'F');
          
          // Indicator text
          pdf.setTextColor(...black);
          pdf.setFontSize(9);
          pdf.setFont('helvetica', 'normal');
          const indLines = pdf.splitTextToSize(String(indicator), contentWidth - 10);
          indLines.forEach(line => {
            pdf.text(line, margin + 6, y + 1.5);
            y += 5;
          });
          y += 2;
        });
        
        y += 5;
      }
      
      // ===== DETECTED ISSUES (if any) =====
      const issues = report.issues || [];
      if (issues.length > 0) {
        checkNewPage(35);
        
        pdf.setTextColor(...lightMuted);
        pdf.setFontSize(7);
        pdf.setFont('helvetica', 'bold');
        pdf.text(spacedText('DETECTED ISSUES'), margin, y);
        y += 3;
        pdf.setDrawColor(...borderClr);
        pdf.setLineWidth(0.15);
        pdf.line(margin, y, pageWidth - margin, y);
        y += 8;
        
        issues.forEach((issue, idx) => {
          checkNewPage(10);
          pdf.setFillColor(...statusColor);
          pdf.circle(margin + 2, y + 0.7, 0.5, 'F');
          pdf.setTextColor(...black);
          pdf.setFontSize(9);
          pdf.setFont('helvetica', 'normal');
          const issLines = pdf.splitTextToSize(String(issue), contentWidth - 10);
          issLines.forEach(line => {
            pdf.text(line, margin + 6, y + 1.5);
            y += 5;
          });
          y += 2;
        });
        
        y += 5;
      }
      
      // ===== FOOTER — Minimal =====
      const footerY = pageHeight - 15;
      
      pdf.setTextColor(...lightMuted);
      pdf.setFontSize(6);
      pdf.setFont('helvetica', 'bold');
      pdf.text(spacedText('© 2026 PHISHNET'), margin, footerY);
      
      const copyW = pdf.getTextWidth(spacedText('© 2026 PHISHNET'));
      pdf.text(spacedText('SECURITY OPERATIONS'), margin + copyW + 8, footerY);
      
      // Shield circle icon on right
      const shieldCX = pageWidth - margin - 4;
      const shieldCY = footerY - 1.5;
      pdf.setDrawColor(...borderClr);
      pdf.setLineWidth(0.3);
      pdf.circle(shieldCX, shieldCY, 3.5, 'S');
      pdf.setTextColor(...lightMuted);
      pdf.setFontSize(6);
      pdf.setFont('helvetica', 'normal');
      pdf.text('S', shieldCX - 1.2, shieldCY + 1.2);
      
      // Save PDF
      pdf.save(fileName);
      if (window.reportsManager) window.reportsManager.showNotification('PDF downloaded successfully!', 'success');
      
      return;
    }

    // Fallback / bulk export path: export container element(s) to PDF via html2canvas slicing
    const element = document.getElementById(elementId);
    if (!element) {
      console.error('Element not found:', elementId);
      if (window.reportsManager) window.reportsManager.showNotification('Could not find report content', 'error');
      return;
    }

    if (window.reportsManager) window.reportsManager.showNotification('Generating PDF...', 'info');

    const clonedElement = element.cloneNode(true);
    const closeBtn = clonedElement.querySelector('.filtered-reports-modal-close');
    const footer = clonedElement.querySelector('.filtered-reports-modal-footer');
    if (closeBtn) closeBtn.remove();
    if (footer) footer.remove();

    const modalBody = clonedElement.querySelector('.filtered-reports-modal-body');
    if (modalBody) { 
      modalBody.style.overflow = 'visible'; 
      modalBody.style.maxHeight = 'none';
      modalBody.style.width = '100%';
      modalBody.style.boxSizing = 'border-box';
    }

    // Ensure modal window is properly constrained for PDF
    const modalWindow = clonedElement.querySelector('.filtered-reports-modal-window');
    if (modalWindow) {
      modalWindow.style.maxHeight = 'none';
      modalWindow.style.width = '100%';
      modalWindow.style.maxWidth = '1200px';
      modalWindow.style.boxSizing = 'border-box';
    }

    // Ensure all nested cards are properly sized
    const modalCards = clonedElement.querySelectorAll('.modal-report-card');
    modalCards.forEach(card => {
      card.style.width = '100%';
      card.style.maxWidth = '100%';
      card.style.boxSizing = 'border-box';
      card.style.overflow = 'hidden';
    });

    const rect = element.getBoundingClientRect();
    clonedElement.style.position = 'absolute';
    clonedElement.style.left = '-9999px';
    clonedElement.style.top = '0';
    clonedElement.style.width = rect.width + 'px';
    clonedElement.style.height = 'auto';
    clonedElement.style.visibility = 'visible';
    clonedElement.style.opacity = '1';
    clonedElement.style.pointerEvents = 'none';
    const bg = getComputedStyle(element).background || getComputedStyle(element).backgroundColor;
    if (bg) clonedElement.style.background = bg;
    document.body.appendChild(clonedElement);

    await new Promise(resolve => requestAnimationFrame(resolve));

    // safe single-canvas or sliced path
    const scale = Math.min(2, (window.devicePixelRatio || 1.5));
    const MAX_CANVAS_DIM = 32768;
    const totalCssHeight = clonedElement.scrollHeight || clonedElement.offsetHeight || clonedElement.clientHeight || 0;
    const estimatedHeight = Math.ceil(totalCssHeight * scale);

    const pdfDoc = new jsPDF('p', 'mm', 'a4');
    const PAGE_WIDTH_MM = pdfDoc.internal.pageSize.getWidth();
    const PAGE_HEIGHT_MM = pdfDoc.internal.pageSize.getHeight();
    const PAGE_MARGIN_MM = 8;
    const USABLE_WIDTH_MM = PAGE_WIDTH_MM - PAGE_MARGIN_MM * 2;

    if (estimatedHeight > MAX_CANVAS_DIM) {
      // sliced capture (unchanged behavior, but keep concise)
      const cssPxPerMm = (clonedElement.offsetWidth || rect.width || 720) / USABLE_WIDTH_MM;
      const pageHeightCss = Math.max(400, Math.floor(PAGE_HEIGHT_MM * cssPxPerMm));
      const totalHeight = totalCssHeight;
      const slices = Math.ceil(totalHeight / pageHeightCss);

      for (let i = 0; i < slices; i++) {
        const wrapper = document.createElement('div');
        wrapper.style.position = 'fixed';
        wrapper.style.left = '0';
        wrapper.style.top = '0';
        wrapper.style.width = clonedElement.offsetWidth + 'px';
        wrapper.style.height = pageHeightCss + 'px';
        wrapper.style.overflow = 'hidden';
        wrapper.style.opacity = '1';
        wrapper.style.zIndex = '99999';
        wrapper.style.pointerEvents = 'none';
        wrapper.style.background = getComputedStyle(clonedElement).background || '#ffffff';

        const inner = clonedElement.cloneNode(true);
        inner.style.margin = '0';
        inner.style.position = 'relative';
        inner.style.left = '0';
        inner.style.top = '0';
        inner.style.transform = `translateY(-${i * pageHeightCss}px)`;
        inner.style.willChange = 'transform';

        wrapper.appendChild(inner);
        document.body.appendChild(wrapper);

        try {
          const sliceCanvas = await html2canvas(wrapper, { scale, useCORS: true, backgroundColor: null, logging: false });
          const sliceData = sliceCanvas.toDataURL('image/png');
          const pxPerMm = sliceCanvas.width / USABLE_WIDTH_MM;
          const renderHeightMm = sliceCanvas.height / pxPerMm;
          if (i > 0) pdfDoc.addPage();
          pdfDoc.addImage(sliceData, 'PNG', PAGE_MARGIN_MM, 0, USABLE_WIDTH_MM, renderHeightMm);
        } catch (e) {
          console.error('[ReportsManager][PDF] slice html2canvas failed', e);
        }

        try { document.body.removeChild(wrapper); } catch (e) {}
      }

      try { document.body.removeChild(clonedElement); } catch (e) {}
      pdfDoc.save(fileName);
      if (window.reportsManager) window.reportsManager.showNotification('PDF downloaded successfully!', 'success');
    } else {
      const canvas = await html2canvas(clonedElement, { scale, useCORS: true, backgroundColor: null, logging: false });
      try { document.body.removeChild(clonedElement); } catch (e) {}

      const imgData = canvas.toDataURL('image/png');
      const pdfFinal = new jsPDF('p', 'mm', 'a4');
      const pdfWidth = pdfFinal.internal.pageSize.getWidth();
      const pdfHeight = pdfFinal.internal.pageSize.getHeight();
      const imgWidth = pdfWidth;
      const imgHeight = (canvas.height * imgWidth) / canvas.width;

      let heightLeft = imgHeight;
      let position = 0;

      pdfFinal.addImage(imgData, 'PNG', 0, position, imgWidth, imgHeight);
      heightLeft -= pdfHeight;

      while (heightLeft > 0) {
        position = heightLeft - imgHeight;
        pdfFinal.addPage();
        pdfFinal.addImage(imgData, 'PNG', 0, position, imgWidth, imgHeight);
        heightLeft -= pdfHeight;
      }

      pdfFinal.save(fileName);
      if (window.reportsManager) window.reportsManager.showNotification('PDF downloaded successfully!', 'success');
    }
  } catch (error) {
    console.error('PDF generation error:', error);
    if (window.reportsManager) window.reportsManager.showNotification('Failed to generate PDF', 'error');
  }
}

// Make function globally available
window.downloadReportAsPDF = downloadReportAsPDF;

// Initialize
const reportsManager = new ReportsManager();
window.reportsManager = reportsManager;
