// Dashboard Data Loader - Updates dashboard with real scan data
// Works alongside scanning-system.js to display real data

class DashboardDataLoader {
  constructor() {
    this._cachedScanHistory = [];
    this.stats = {
      totalScans: 0,
      threatsBlocked: 0,
      safeItems: 0,
      protectionRate: 0
    };
  }

  get scanHistory() {
    return this.getScanHistory();
  }

  set scanHistory(val) {
    this._cachedScanHistory = val;
  }

  getScanHistory() {
    if (window.scanSystem && window.scanSystem.scanHistory) {
      return window.scanSystem.scanHistory;
    }
    if (window.scanManager && window.scanManager.scanHistory) {
      return window.scanManager.scanHistory;
    }
    if (window.scanningSystem && window.scanningSystem.scanHistory) {
      return window.scanningSystem.scanHistory;
    }
    return this._cachedScanHistory || [];
  }

  async init() {
    console.log('[DashboardData] Initializing dashboard data...');
    
    // Wait for scanning system to be ready and share its data
    await this.waitForScanHistory();
    
    this.updateDashboardStats();
    this.updateRecentAlertsUI();
    this.updateRecentScansTable();
    this.updateChart();
    
    // Check for data breaches
    this.checkDataBreaches();

    // No polling needed - refreshDashboardData() handles live updates
    
    console.log('[DashboardData] Dashboard updated with', this.scanHistory.length, 'scans');
  }

  async waitForScanHistory() {
    // ── Instant Cache Load ──
    // Load cached history first so the user sees immediate data
    const localHistory = localStorage.getItem('scanHistory');
    if (localHistory) {
      try {
        this.scanHistory = JSON.parse(localHistory);
        console.log('[DashboardData] Pre-loaded', this.scanHistory.length, 'scans from localStorage');
        // Instantly render UI from cache so that it doesn't look blank
        this.updateDashboardStats();
        this.updateRecentAlertsUI();
        this.updateRecentScansTable();
        this.updateChart();
      } catch (e) {
        this.scanHistory = [];
      }
    }

    // Wait up to 20 seconds for ScanningSystem to complete loading server data
    const maxWait = 20000;
    const interval = 100;
    let waited = 0;
    
    while (waited < maxWait) {
      // Check if ScanningSystem has loaded scan history (window.scanSystem)
      // Use _historyLoaded flag to ensure loadScanHistory() has completed (not just initialized to [])
      if (window.scanSystem && window.scanSystem.scanHistory && (window.scanSystem._historyLoaded || window.scanSystem.scanHistory.length > 0)) {
        this.scanHistory = window.scanSystem.scanHistory;
        console.log('[DashboardData] Using data from scanSystem:', this.scanHistory.length, 'scans');
        return;
      }
      
      // Also check scanManager or scanningSystem
      if (window.scanManager && window.scanManager.scanHistory && (window.scanManager._historyLoaded || window.scanManager.scanHistory.length > 0)) {
        this.scanHistory = window.scanManager.scanHistory;
        console.log('[DashboardData] Using data from scanManager:', this.scanHistory.length, 'scans');
        return;
      }
      
      if (window.scanningSystem && window.scanningSystem.scanHistory && (window.scanningSystem._historyLoaded || window.scanningSystem.scanHistory.length > 0)) {
        this.scanHistory = window.scanningSystem.scanHistory;
        console.log('[DashboardData] Using data from scanningSystem:', this.scanHistory.length, 'scans');
        return;
      }
      
      await new Promise(resolve => setTimeout(resolve, interval));
      waited += interval;
    }
    
    // Fallback: load from localStorage directly
    console.log('[DashboardData] Scanning system not ready, loading from localStorage');
    const fallbackHistory = localStorage.getItem('scanHistory');
    if (fallbackHistory) {
      try {
        this.scanHistory = JSON.parse(fallbackHistory);
        console.log('[DashboardData] Loaded', this.scanHistory.length, 'scans from localStorage');
      } catch (e) {
        this.scanHistory = [];
      }
    }
  }

  extractDomain(url) {
    try {
      if (!url) return 'unknown';
      if (url.includes('@')) {
        return url.split('@')[1];
      }
      const parsed = new URL(url.startsWith('http') ? url : `http://${url}`);
      return parsed.hostname;
    } catch {
      return url;
    }
  }

  updateDashboardStats() {
    try {
      // Normalize threat values for counting
      const getThreat = (s) => {
        if (!s) return 'unknown';
        const t = (s.threat || s.status || '').toString().toLowerCase();
        if (t === 'safe' || t === 'legitimate' || s.isSafe === true) return 'safe';
        if (t === 'malicious' || t === 'phishing' || s.isSafe === false) return 'malicious';
        if (t === 'suspicious') return 'suspicious';
        return 'unknown';
      };
      
      const safe = (this.scanHistory || []).filter(s => getThreat(s) === 'safe').length;
      const malicious = (this.scanHistory || []).filter(s => getThreat(s) === 'malicious').length;
      const suspicious = (this.scanHistory || []).filter(s => getThreat(s) === 'suspicious').length;
      
      // Use the real total from the server if available (not capped by the 500 limit)
      // Falls back to scanHistory.length if no server total is available
      const serverTotal = (window.scanSystem && window.scanSystem.totalServerScans)
        ? window.scanSystem.totalServerScans
        : (window.scanManager && window.scanManager.totalServerScans)
          ? window.scanManager.totalServerScans
          : null;
      
      const total = serverTotal || (this.scanHistory || []).length;
      
      // For threats/safe counts from loaded items, scale proportionally if total > loaded
      const loadedTotal = (this.scanHistory || []).length;
      const safeFinal = total > loadedTotal ? Math.round(safe * (total / loadedTotal)) : safe;
      const threatsFinal = total > loadedTotal ? total - safeFinal : malicious + suspicious;
      
      this.stats = {
        totalScans: total,
        threatsBlocked: malicious + suspicious,
        safeItems: total - (malicious + suspicious),
        protectionRate: total > 0 ? (((total - (malicious + suspicious)) / total) * 100).toFixed(1) : 0
      };

      console.log('[DashboardData] Stats:', this.stats);

      // Update stat elements by ID (primary method)
      const totalEl = document.getElementById('total-scans');
      const threatsEl = document.getElementById('threats-blocked');
      const safeEl = document.getElementById('safe-items');
      const rateEl = document.getElementById('protection-rate');
      
      if (totalEl) totalEl.textContent = this.stats.totalScans.toLocaleString();
      if (threatsEl) threatsEl.textContent = this.stats.threatsBlocked.toLocaleString();
      if (safeEl) safeEl.textContent = this.stats.safeItems.toLocaleString();
      if (rateEl) rateEl.textContent = `${this.stats.protectionRate}%`;
    } catch (e) {
      console.error('[DashboardData] Error in updateDashboardStats:', e);
    }
    
    // Also update stats-grid cards as fallback
    const statsGrid = document.querySelector('.stats-grid');
    if (statsGrid) {
      const cards = statsGrid.querySelectorAll('.card');
      cards.forEach((card, index) => {
        const h2 = card.querySelector('h2');
        if (!h2) return;
        switch(index) {
          case 0: h2.textContent = this.stats.totalScans.toLocaleString(); break;
          case 1: h2.textContent = this.stats.threatsBlocked.toLocaleString(); break;
          case 2: h2.textContent = this.stats.safeItems.toLocaleString(); break;
          case 3: h2.textContent = `${this.stats.protectionRate}%`; break;
        }
      });
    }
  }

  updateRecentAlertsUI() {
    const alertsContainer = document.getElementById('alerts-content');
    if (!alertsContainer) return;
    
    // Get threats (malicious and suspicious only)
    const getThreat = (s) => {
      const t = (s.threat || '').toLowerCase();
      if (t === 'safe' || t === 'legitimate' || s.isSafe === true) return 'safe';
      if (t === 'malicious' || t === 'phishing' || s.isSafe === false) return 'malicious';
      if (t === 'suspicious') return 'suspicious';
      return 'unknown';
    };
    
    const threats = this.scanHistory
      .filter(s => {
        const threat = getThreat(s);
        return threat === 'malicious' || threat === 'suspicious';
      })
      .slice(0, 5);
    
    if (threats.length === 0) {
      alertsContainer.innerHTML = `
        <div class="dash-alert-item" style="text-align: center; padding: 1.5rem; justify-content: center;">
          <div style="display:flex;flex-direction:column;align-items:center;gap:0.3rem;">
            <span style="color: #00FF88; font-size: 0.85rem; font-weight: 600;">✓ No threats detected</span>
            <span style="color: var(--text-muted); font-size: 0.78rem;">Your scans are all clean!</span>
          </div>
        </div>
      `;
      return;
    }
    
    alertsContainer.innerHTML = threats.map(threat => this.createAlertHTML(threat)).join('');
  }

  createAlertHTML(item) {
    const threat = (item.threat || '').toLowerCase();
    const isMalicious = threat === 'malicious' || threat === 'phishing';
    const isSuspicious = threat === 'suspicious';
    
    const dotColor = isMalicious ? '#FF4D4D' : '#FFC107';
    const badgeClass = isMalicious ? 'dash-badge-malicious' : 'dash-badge-suspicious';
    const badgeText = isMalicious ? 'Malicious' : 'Suspicious';
    const itemType = item.type || (item.value && item.value.includes('@') ? 'email' : 'url');
    const title = itemType === 'email' ? 'Phishing Email Detected' : 'Suspicious URL Blocked';
    const itemValue = item.value || item.url || '';
    const description = itemType === 'email' 
      ? `From: ${itemValue}` 
      : this.extractDomain(itemValue);
    
    const timestamp = item.timestamp || Date.now();
    const timeAgo = this.getTimeAgo(timestamp);
    
    return `
      <div class="dash-alert-item">
        <div class="dash-alert-dot" style="background: ${dotColor};"></div>
        <div class="dash-alert-body">
          <span class="dash-alert-title">${title}</span>
          <span class="dash-alert-desc">${description}</span>
          <div class="dash-alert-meta">
            <span class="dash-alert-badge ${badgeClass}">${badgeText}</span>
            <span class="dash-alert-time">${timeAgo}</span>
          </div>
        </div>
      </div>
    `;
  }

  getTimeAgo(timestamp) {
    const now = Date.now();
    const diff = now - timestamp;
    const minutes = Math.floor(diff / 60000);
    const hours = Math.floor(diff / 3600000);
    const days = Math.floor(diff / 86400000);
    
    if (minutes < 1) return 'Just now';
    if (minutes < 60) return `${minutes} minute${minutes > 1 ? 's' : ''} ago`;
    if (hours < 24) return `${hours} hour${hours > 1 ? 's' : ''} ago`;
    return `${days} day${days > 1 ? 's' : ''} ago`;
  }

  updateRecentScansTable() {
    
    // Fallback if ScanningSystem is not available
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
          <p>No scans yet. Scan a URL or email to see results here.</p>
        </div>
      `;
      return;
    }
    
    const visible = this.scanHistory.slice(0, this._scanPageVisible);
    const remaining = this.scanHistory.length - visible.length;
    
    listEl.innerHTML = visible.map(scan => this.createScanCardHTML(scan)).join('');
    
    // Show More / Show Less footer
    if (this.scanHistory.length > PAGE_SIZE) {
      const showingText = remaining > 0
        ? `Showing ${visible.length} of ${this.scanHistory.length}`
        : `Showing all ${this.scanHistory.length} scans`;
      const showMoreBtn = remaining > 0
        ? `<button class="dash-scan-show-more" id="dash-scan-more">Show More (${Math.min(PAGE_SIZE, remaining)})</button>`
        : '';
      const showLessBtn = this._scanPageVisible > PAGE_SIZE
        ? `<button class="dash-scan-show-more" id="dash-scan-less">Show Less</button>`
        : '';
      listEl.insertAdjacentHTML('beforeend', `
        <div class="dash-scan-footer">
          <span class="dash-scan-showing">${showingText}</span>
          <div class="dash-scan-footer-btns">${showMoreBtn}${showLessBtn}</div>
        </div>`);
      document.getElementById('dash-scan-more')?.addEventListener('click', () => {
        this._scanPageVisible += PAGE_SIZE;
        this.updateRecentScansTable();
      });
      document.getElementById('dash-scan-less')?.addEventListener('click', () => {
        this._scanPageVisible = PAGE_SIZE;
        this.updateRecentScansTable();
      });
    }
    
    console.log('[DashboardData] Scan list updated with', visible.length, 'of', this.scanHistory.length, 'scans');
  }

  createScanCardHTML(scan) {
    const threatColors = {
      safe: '#00FF88',
      legitimate: '#00FF88',
      suspicious: '#FFC107',
      malicious: '#FF4D4D',
      phishing: '#FF4D4D'
    };
    
    const threatLabels = {
      safe: 'Safe',
      legitimate: 'Safe',
      suspicious: 'Suspicious',
      malicious: 'Malicious',
      phishing: 'Phishing'
    };
    
    const threatClasses = {
      safe: 'safe',
      legitimate: 'safe',
      suspicious: 'suspicious',
      malicious: 'malicious',
      phishing: 'malicious'
    };
    
    const threat = (scan.threat || 'unknown').toLowerCase();
    const color = threatColors[threat] || (scan.isSafe === true ? '#00FF88' : scan.isSafe === false ? '#FF4D4D' : '#888');
    const label = threatLabels[threat] || (scan.isSafe === true ? 'Safe' : scan.isSafe === false ? 'Malicious' : threat);
    const cls = threatClasses[threat] || (scan.isSafe === true ? 'safe' : scan.isSafe === false ? 'malicious' : '');
    
    const confNum = typeof scan.confidence === 'number' ? scan.confidence : parseFloat(scan.confidence) || 0;
    const confStr = confNum > 0 ? `${confNum.toFixed(0)}%` : 'N/A';
    
    const timestamp = scan.timestamp || Date.now();
    const date = new Date(timestamp);
    const timeStr = date.toLocaleString('en-US', { 
      month: 'short', 
      day: 'numeric',
      hour: '2-digit', 
      minute: '2-digit'
    });
    
    const scanValue = scan.value || scan.url || '';
    const displayValue = scanValue.length > 50 
      ? scanValue.substring(0, 50) + '…' 
      : scanValue;
    
    const scanType = scan.type || (scanValue.includes('@') ? 'email' : 'url');
    const typeIcon = scanType === 'email'
      ? '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="4" width="20" height="16" rx="2"/><path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7"/></svg>'
      : '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>';
    const scanId = scan.id || scan._id || scanValue;
    
    return `
      <div class="dash-scan-card" onclick="dashboardData.viewScanDetails('${scanId.replace(/'/g, "\\'")}')">
        <div class="dash-scan-status dash-scan-${cls}">
          <span class="dash-scan-dot" style="background:${color}"></span>
        </div>
        <div class="dash-scan-info">
          <div class="dash-scan-target" title="${scanValue}">${displayValue}</div>
          <div class="dash-scan-meta-row">
            <span class="dash-scan-type">${typeIcon} ${scanType === 'email' ? 'Email' : 'URL'}</span>
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
      </div>
    `;
  }

  viewScanDetails(id) {
    const scan = this.scanHistory.find(s => (s.id || s._id || s.value) === id || s.value === id);
    if (scan) {
      const value = scan.value || scan.url || '';
      const threat = scan.threat || (scan.isSafe === true ? 'safe' : scan.isSafe === false ? 'malicious' : 'unknown');
      const riskFactors = scan.riskFactors || scan.indicators || scan.issues || [];
      alert(`Scan Details:\n\nTarget: ${value}\nType: ${scan.type || (value.includes('@') ? 'email' : 'url')}\nResult: ${threat}\nConfidence: ${scan.confidence || 'N/A'}%\n\nRisk Factors:\n${riskFactors.join('\n') || 'None'}`);
    }
  }

  updateChart() {
    try {
      if (typeof Chart === 'undefined' || !window.threatChartInstance) {
        console.log('[DashboardData] Chart not ready, will update when available');
        return;
      }
      
      // Helper to normalize threat
      const getThreat = (s) => {
        if (!s) return 'unknown';
        const t = (s.threat || s.status || '').toString().toLowerCase();
        if (t === 'safe' || t === 'legitimate' || s.isSafe === true) return 'safe';
        if (t === 'malicious' || t === 'phishing' || s.isSafe === false) return 'malicious';
        if (t === 'suspicious') return 'suspicious';
        return 'unknown';
      };
      
      // Group scans by day for last 7 days
      const now = new Date();
      const days = [];
      const maliciousData = [];
      const suspiciousData = [];
      const safeData = [];
      
      for (let i = 6; i >= 0; i--) {
        const date = new Date(now);
        date.setDate(date.getDate() - i);
        const dayStr = date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
        days.push(dayStr);
        
        const dayStart = new Date(date.setHours(0, 0, 0, 0)).getTime();
        const dayEnd = new Date(date.setHours(23, 59, 59, 999)).getTime();
        
        const dayScans = (this.scanHistory || []).filter(s => {
          if (!s) return false;
          const ts = s.timestamp || Date.now();
          return ts >= dayStart && ts <= dayEnd;
        });
        
        maliciousData.push(dayScans.filter(s => getThreat(s) === 'malicious').length);
        suspiciousData.push(dayScans.filter(s => getThreat(s) === 'suspicious').length);
        safeData.push(dayScans.filter(s => getThreat(s) === 'safe').length);
      }
      
      // Update chart data
      const chart = window.threatChartInstance;
      chart.data.labels = days;
      chart.data.datasets[0].data = maliciousData;
      chart.data.datasets[1].data = suspiciousData;
      chart.data.datasets[2].data = safeData;
      chart.update();
      
      console.log('[DashboardData] Chart updated with real data');
    } catch (e) {
      console.error('[DashboardData] Error updating chart:', e);
    }
  }

  async checkDataBreaches() {
    console.log('[DashboardData] Checking for data breaches...');
    try {
      const token = localStorage.getItem('token');
      if (!token) return;

      const response = await fetch(window.getApiUrl(window.API_CONFIG.api.endpoints.breach.check), {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      const result = await response.json();
      
      if (result.success && result.data.breachCount > 0) {
        this.renderBreachAlert(result.data);
      }
    } catch (error) {
      console.error('[DashboardData] Error checking data breaches:', error);
    }
  }

  renderBreachAlert(data) {
    const container = document.getElementById('breach-alert-container');
    if (!container) return;

    const breachNames = data.breaches.map(b => `${b.Name} (${new Date(b.BreachDate).getFullYear()})`).join(', ');

    container.innerHTML = `
      <div style="background-color: rgba(255, 77, 77, 0.1); border: 1px solid #FF4D4D; border-radius: 8px; padding: 1.5rem; display: flex; gap: 1rem; align-items: flex-start;">
        <div style="color: #FF4D4D; background: rgba(255, 77, 77, 0.2); padding: 0.5rem; border-radius: 50%;">
          <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><path d="M12 9v4"/><path d="M12 17h.01"/></svg>
        </div>
        <div style="flex: 1;">
          <h3 style="color: #FF4D4D; margin: 0 0 0.5rem 0; font-size: 1.1rem; display: flex; align-items: center; gap: 0.5rem;">
            Dark Web Alert: Your email was found in ${data.breachCount} data breach${data.breachCount !== 1 ? 'es' : ''}!
            ${data.isMockData ? '<span style="font-size: 0.7rem; background: #FFC107; color: #000; padding: 2px 6px; border-radius: 4px; vertical-align: middle;">Simulation</span>' : ''}
          </h3>
          <p style="color: var(--text-color); margin: 0 0 0.5rem 0; font-size: 0.95rem;">
            Your email address (<strong>${data.email}</strong>) appeared in the following known breaches: 
            <span style="color: var(--text-muted);">${breachNames}</span>.
          </p>
          <p style="color: var(--text-muted); margin: 0; font-size: 0.85rem;">
            We strongly recommend updating your passwords immediately and enabling Two-Factor Authentication on your important accounts.
          </p>
        </div>
        <button onclick="document.getElementById('breach-alert-container').style.display='none'" style="background: none; border: none; color: var(--text-muted); cursor: pointer; padding: 0.25rem;">
          <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
        </button>
      </div>
    `;
    container.style.display = 'block';
  }
}

// Initialize when DOM is ready
let dashboardData;

function initDashboardData() {
  // Only init on dashboard page
  if (!window.location.pathname.includes('dashboard')) return;
  
  console.log('[DashboardData] Starting initialization...');
  dashboardData = new DashboardDataLoader();
  dashboardData.init();
  window.dashboardData = dashboardData;
}

// Initialize immediately - no artificial delay
// waitForScanHistory() handles the async wait for server data
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initDashboardData);
} else {
  initDashboardData();
}

// Expose a refresh function for when new scans are added
window.refreshDashboardData = function() {
  if (dashboardData) {
    // Re-sync with scanning system
    if (window.scanSystem && window.scanSystem.scanHistory) {
      dashboardData.scanHistory = window.scanSystem.scanHistory;
    } else if (window.scanManager && window.scanManager.scanHistory) {
      dashboardData.scanHistory = window.scanManager.scanHistory;
    }
    dashboardData.updateDashboardStats();
    dashboardData.updateRecentAlertsUI();
    dashboardData.updateRecentScansTable();
    dashboardData.updateChart();
  } else {
    // Instantiate immediately if it hasn't been done yet
    if (window.location.pathname.includes('dashboard')) {
      console.log('[DashboardData] refreshDashboardData called early, initializing now...');
      dashboardData = new DashboardDataLoader();
      dashboardData.init();
      window.dashboardData = dashboardData;
    }
  }
};
