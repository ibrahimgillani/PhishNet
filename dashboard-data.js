// Dashboard Data Loader - Updates dashboard with real scan data
// Works alongside scanning-system.js to display real data

class DashboardDataLoader {
  constructor() {
    this.scanHistory = [];
    this.stats = {
      totalScans: 0,
      threatsBlocked: 0,
      safeItems: 0,
      protectionRate: 0
    };
  }

  async init() {
    console.log('[DashboardData] Initializing dashboard data...');
    
    // Wait for scanning system to be ready and share its data
    await this.waitForScanHistory();
    
    this.updateDashboardStats();
    this.updateRecentAlertsUI();
    this.updateRecentScansTable();
    this.updateChart();
    
    console.log('[DashboardData] Dashboard updated with', this.scanHistory.length, 'scans');
  }

  async waitForScanHistory() {
    // Wait up to 5 seconds for ScanningSystem to load data
    const maxWait = 5000;
    const interval = 100;
    let waited = 0;
    
    while (waited < maxWait) {
      // Check if ScanningSystem has loaded scan history (window.scanSystem)
      if (window.scanSystem && window.scanSystem.scanHistory && window.scanSystem.scanHistory.length >= 0) {
        this.scanHistory = window.scanSystem.scanHistory;
        console.log('[DashboardData] Using data from scanSystem:', this.scanHistory.length, 'scans');
        return;
      }
      
      // Also check scanManager or scanningSystem
      if (window.scanManager && window.scanManager.scanHistory) {
        this.scanHistory = window.scanManager.scanHistory;
        console.log('[DashboardData] Using data from scanManager:', this.scanHistory.length, 'scans');
        return;
      }
      
      if (window.scanningSystem && window.scanningSystem.scanHistory) {
        this.scanHistory = window.scanningSystem.scanHistory;
        console.log('[DashboardData] Using data from scanningSystem:', this.scanHistory.length, 'scans');
        return;
      }
      
      await new Promise(resolve => setTimeout(resolve, interval));
      waited += interval;
    }
    
    // Fallback: load from localStorage directly
    console.log('[DashboardData] Scanning system not ready, loading from localStorage');
    const localHistory = localStorage.getItem('scanHistory');
    if (localHistory) {
      try {
        this.scanHistory = JSON.parse(localHistory);
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
    // Normalize threat values for counting
    const getThreat = (s) => {
      const t = (s.threat || '').toLowerCase();
      if (t === 'safe' || t === 'legitimate' || s.isSafe === true) return 'safe';
      if (t === 'malicious' || t === 'phishing' || s.isSafe === false) return 'malicious';
      if (t === 'suspicious') return 'suspicious';
      return 'unknown';
    };
    
    const safe = this.scanHistory.filter(s => getThreat(s) === 'safe').length;
    const malicious = this.scanHistory.filter(s => getThreat(s) === 'malicious').length;
    const suspicious = this.scanHistory.filter(s => getThreat(s) === 'suspicious').length;
    const total = this.scanHistory.length;
    
    this.stats = {
      totalScans: total,
      threatsBlocked: malicious + suspicious,
      safeItems: safe,
      protectionRate: total > 0 ? ((safe / total) * 100).toFixed(1) : 0
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
        <div class="alert-item-enhanced" style="text-align: center; padding: 2rem;">
          <p style="color: #00FF88;">✓ No threats detected</p>
          <p style="color: #888; font-size: 0.875rem;">Your scans are all clean!</p>
        </div>
      `;
      return;
    }
    
    alertsContainer.innerHTML = threats.map(threat => this.createAlertHTML(threat)).join('');
  }

  createAlertHTML(item) {
    const threat = (item.threat || '').toLowerCase();
    const isMalicious = threat === 'malicious' || threat === 'phishing' || item.isSafe === false;
    const iconSvg = isMalicious 
      ? '<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>'
      : '<circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>';
    
    const badgeClass = isMalicious ? 'alert-type-malicious' : 'alert-type-suspicious';
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
      <div class="alert-item-enhanced">
        <div class="alert-item-header">
          <div class="alert-icon">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              ${iconSvg}
            </svg>
          </div>
          <div class="alert-content">
            <h4 class="alert-title">${title}</h4>
            <p class="alert-description">${description}</p>
            <span class="alert-type-badge ${badgeClass}">${badgeText}</span>
            <p class="alert-time">${timeAgo}</p>
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
    // Let ScanningSystem handle the table if it's available
    // We just update the stats
    if (window.scanSystem && typeof window.scanSystem.updateDashboardTable === 'function') {
      console.log('[DashboardData] Using scanSystem for table updates');
      window.scanSystem.updateDashboardTable();
      return;
    }
    
    // Fallback if ScanningSystem is not available
    const tbody = document.querySelector('#scan-results-table tbody');
    if (!tbody) return;
    
    const recentScans = this.scanHistory.slice(0, 10);
    
    if (recentScans.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="6" style="text-align: center; padding: 2rem; color: #888;">
            No scans yet. Scan a URL or email to see results here.
          </td>
        </tr>
      `;
      return;
    }
    
    tbody.innerHTML = recentScans.map(scan => this.createTableRowHTML(scan)).join('');
    console.log('[DashboardData] Table updated with', recentScans.length, 'recent scans');
  }

  createTableRowHTML(scan) {
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
    
    const threat = (scan.threat || 'unknown').toLowerCase();
    const color = threatColors[threat] || (scan.isSafe === true ? '#00FF88' : scan.isSafe === false ? '#FF4D4D' : '#888');
    const label = threatLabels[threat] || (scan.isSafe === true ? 'Safe' : scan.isSafe === false ? 'Malicious' : threat);
    
    const confidence = typeof scan.confidence === 'number' 
      ? `${scan.confidence.toFixed(1)}%` 
      : scan.confidence || 'N/A';
    
    const timestamp = scan.timestamp || Date.now();
    const date = new Date(timestamp);
    const timeStr = date.toLocaleString('en-US', { 
      month: 'short', 
      day: 'numeric',
      hour: '2-digit', 
      minute: '2-digit'
    });
    
    const scanValue = scan.value || scan.url || '';
    const displayValue = scanValue.length > 40 
      ? scanValue.substring(0, 40) + '...' 
      : scanValue;
    
    const scanType = scan.type || (scanValue.includes('@') ? 'email' : 'url');
    const scanId = scan.id || scan._id || scanValue;
    
    return `
      <tr>
        <td title="${scanValue}">${displayValue}</td>
        <td>${scanType === 'email' ? 'Email' : 'URL'}</td>
        <td><span style="color: ${color}; font-weight: 600;">${label}</span></td>
        <td>${confidence}</td>
        <td>${timeStr}</td>
        <td>
          <button class="btn btn-sm btn-secondary" onclick="dashboardData.viewScanDetails('${scanId}')" style="padding: 0.25rem 0.5rem; font-size: 0.75rem;">
            View
          </button>
        </td>
      </tr>
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
    if (typeof Chart === 'undefined' || !window.threatChartInstance) {
      console.log('[DashboardData] Chart not ready, will update when available');
      return;
    }
    
    // Helper to normalize threat
    const getThreat = (s) => {
      const t = (s.threat || '').toLowerCase();
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
      
      const dayScans = this.scanHistory.filter(s => {
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

// Wait for DOM and scanning system to be ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    // Give scanning system time to load first
    setTimeout(initDashboardData, 500);
  });
} else {
  setTimeout(initDashboardData, 500);
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
  }
};
