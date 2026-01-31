// Report Viewer Module
class ReportViewer {
  constructor() {
    this.currentReport = null;
    this.init();
  }

  init() {
    document.addEventListener('DOMContentLoaded', () => {
      this.loadReport();
    });
  }

  // Normalize values coming from server/localStorage
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
        const m = s.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i);
        if (m) return m[0];
        const m2 = s.match(/([A-Z0-9._%+-]+)\s*@\s*([A-Z0-9.-]+)\s*\.\s*([A-Z]{2,})/i);
        if (m2) return (m2[1] + '@' + m2[2] + '.' + m2[3]).replace(/\s+/g, '');
        return '';
      } catch (e) { return ''; }
    };
    if (!report) return '';
    const type = (report.type || '').toString().toLowerCase();
    if (type.indexOf('email') !== -1) return report.senderEmail || extractEmail(report.value) || '';
    return report.value || report.url || '';
  }

  loadReport() {
    // Get report ID from URL query parameter (support both `id` and legacy `scanId`)
    const params = new URLSearchParams(window.location.search);
    const reportId = params.get('id') || params.get('scanId');

    if (!reportId) {
      this.showEmptyState('No report ID provided');
      return;
    }

    const token = localStorage.getItem('token');

    if (!token) {
      // Non-logged-in: load from localStorage
      // Prefer the explicit selectedScan if present (may contain richer fields)
      try {
        const stored = localStorage.getItem('selectedScan');
        if (stored) {
          const parsedSel = JSON.parse(stored);
          if (parsedSel && String(parsedSel.id) === String(reportId)) {
            this.currentReport = parsedSel;
            this.renderReport(parsedSel);
            this.setupActionButtons();
            return;
          }
        }
      } catch (e) {}

      const scanHistory = JSON.parse(localStorage.getItem('scanHistory')) || [];
      const report = scanHistory.find(scan => String(scan.id) === String(reportId));

      if (!report) {
        this.showEmptyState('Report not found. It may have been deleted.');
        return;
      }

      this.currentReport = report;
      this.renderReport(report);
      this.setupActionButtons();
      return;
    }

    // Logged-in: fetch recent history from server and find the report by id
    fetch(getApiUrlWithParams(window.API_CONFIG.api.endpoints.users.history, { limit: 200 }), {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      }
    }).then(res => res.ok ? res.json() : Promise.reject(res)).then(data => {
      if (!data.success) throw new Error(data.message || 'Failed to load history');
      const history = data.data.history || [];
        const mapped = history.map(item => {
        const rawThreat = item.threatLevel || item.threat || item.status || (item.isSafe === true ? 'safe' : (item.isSafe === false ? 'malicious' : null));
        const threat = rawThreat && ['safe','suspicious','malicious'].includes(String(rawThreat).toLowerCase()) ? String(rawThreat).toLowerCase() : (this.mapThreatLevel ? this.mapThreatLevel(rawThreat) : (rawThreat || 'safe'));

        const rawRisk = this.sanitizeValue(item.riskLevel) || this.sanitizeValue(item.risk) || this.sanitizeValue(item.analysis && item.analysis.riskLevel) || null;
        let indicators = item.indicators || (item.analysis && item.analysis.indicators) || [];
        if (!Array.isArray(indicators)) indicators = [];
        indicators = indicators.map(i => this.sanitizeValue(i)).filter(i => i !== null);
        let issues = item.issues || (item.analysis && item.analysis.issues) || [];
        if (!Array.isArray(issues)) issues = [];
        issues = issues.map(i => this.sanitizeValue(i)).filter(i => i !== null);
        const summary = this.sanitizeValue(item.summary) || this.sanitizeValue(item.analysis && item.analysis.summary) || this.sanitizeValue(item.details) || '';

        // derive readable risk level if missing
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

        const computedRisk = deriveRisk(rawRisk, threat, item.threatLevel || item.threatLevel);

        return {
        id: String(item._id),
        type: item.scanType || (item.url && item.url.includes('@') ? 'email' : 'url'),
        value: item.url || item.value || item.senderEmail || '',
        threat: threat,
        confidence: item.confidence || null,
        riskLevel: computedRisk || rawRisk || null,
        timestamp: item.checkedAt ? new Date(item.checkedAt).getTime() : Date.now(),
        date: item.checkedAt ? new Date(item.checkedAt).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' }) : '',
        time: item.checkedAt ? new Date(item.checkedAt).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: true }) : '',
        indicators: indicators,
        issues: issues,
        summary: summary,
        scanDetails: item.details || item.scanDetails || item.analysis || {}
      };
      });

      const report = mapped.find(r => String(r.id) === String(reportId));
      if (!report) {
        this.showEmptyState('Report not found. It may have been deleted.');
        return;
      }

      this.currentReport = report;
      this.renderReport(report);
      this.setupActionButtons();
    }).catch(err => {
      console.error('[ReportViewer] Failed to load report from server:', err);
      // If unauthorized, clear token and cached scan data to prevent leakage
      if (err && err.status === 401) {
        console.warn('[ReportViewer] Unauthorized - clearing token and cached data');
        localStorage.removeItem('token');
        localStorage.removeItem('scanHistory');
        localStorage.removeItem('selectedScan');
        localStorage.removeItem('selectedScanId');
        if (window.reportsManager) window.reportsManager.scanHistory = [];
        this.showEmptyState('Session expired or unauthorized. Please login again.');
        return;
      }
      // Fallback to localStorage
      const scanHistory = JSON.parse(localStorage.getItem('scanHistory')) || [];
      const report = scanHistory.find(scan => String(scan.id) === String(reportId));
      if (!report) {
        this.showEmptyState('Report not found. It may have been deleted.');
        return;
      }
      this.currentReport = report;
      this.renderReport(report);
      this.setupActionButtons();
    });
  }

  renderReport(report) {
    const contentDiv = document.getElementById('report-content');
    
    const threatColor = report.threat === 'safe' ? '#00FF88' : 
                       report.threat === 'suspicious' ? '#FFC107' : '#FF4D4D';
    const threatBg = report.threat === 'safe' ? 'safe' : 
                    report.threat === 'suspicious' ? 'suspicious' : 'malicious';

    const indicatorType = (indicator) => {
      const lowerIndicator = indicator.toLowerCase();
      if (lowerIndicator.includes('valid') || lowerIndicator.includes('✓') || lowerIndicator.includes('good')) {
        return 'safe';
      } else if (lowerIndicator.includes('malicious') || lowerIndicator.includes('blacklist') || lowerIndicator.includes('✕') || lowerIndicator.includes('threat')) {
        return 'threat';
      }
      return 'warning';
    };

    const indicatorsArr = Array.isArray(report.indicators) ? report.indicators : [];
    const issuesArr = Array.isArray(report.issues) ? report.issues : [];

    const indicatorHTML = indicatorsArr.length > 0 ? indicatorsArr.map(indicator => {
      const safeIndicator = this.escapeHtml(indicator || '');
      const type = indicatorType(safeIndicator);
      const iconText = type === 'safe' ? '✓' : type === 'threat' ? '✕' : '⚠';
      const iconColor = type === 'safe' ? '#10B981' : type === 'threat' ? '#EF4444' : '#F59E0B';
      return `
        <li class="indicator-item ${type}">
          <div class="indicator-icon" style="display:flex; align-items:center; justify-content:center; min-width:32px; height:32px; border-radius:50%; background: ${iconColor}; color: #ffffff; font-weight:700;">${iconText}</div>
          <div class="indicator-text">
            <strong style="color: #ffffff; margin-left:8px;">${safeIndicator}</strong>
          </div>
        </li>
      `;
    }).join('') : '<li style="color: #9CA3AF; padding: 0.5rem 0;">No indicators detected</li>';

    const issuesHTML = issuesArr.length > 0 ? issuesArr.map(issue => {
      const safeIssue = this.escapeHtml(issue || '');
      const type = safeIssue.includes('✓') ? 'safe' : safeIssue.includes('✕') ? 'threat' : 'warning';
      return `<div style="padding: 0.75rem; margin-bottom: 0.5rem; background: rgba(255, 255, 255, 0.05); border-left: 3px solid ${type === 'safe' ? '#00FF88' : type === 'threat' ? '#FF4D4D' : '#FFC107'}; border-radius: 4px; color: white;">${safeIssue}</div>`;
    }).join('') : '<div style="color: #9CA3AF; padding: 0.5rem 0;">No issues detected</div>';

    /* headerHTML removed here; a type-specific header is built later */

    // Choose icon symbol and color for the main status
    const statusSymbol = report.threat === 'safe' ? '✓' : report.threat === 'suspicious' ? '⚠' : '✕';
    const statusColor = report.threat === 'safe' ? '#10B981' : report.threat === 'suspicious' ? '#F59E0B' : '#EF4444';

    const statusHTML = `
      <div class="report-card">
        <div class="report-status-section">
          <div class="status-badge-row" style="display:flex; gap:14px; align-items:center;">
            <div style="display:flex; flex-direction:column; align-items:center; gap:8px;">
              <div style="width:56px; height:56px;">
                <svg width="56" height="56" viewBox="0 0 56 56" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="${report.threat} status">
                  <circle cx="28" cy="28" r="26" fill="${statusColor}"></circle>
                  <text x="28" y="36" text-anchor="middle" font-size="22" font-family="Inter, Arial, sans-serif" fill="#ffffff">${statusSymbol}</text>
                </svg>
              </div>
              <div class="status-badge ${threatBg}" style="text-align:center;">
                <div class="status-badge-value" style="font-weight:700;">${(report.threat||'').toUpperCase()}</div>
              </div>
              <div style="font-size:12px; color:var(--text-muted);">Risk: <strong style="color:${statusColor};">${this.formatRisk(report.riskLevel) || 'Unknown'}</strong></div>
            </div>

            <div class="status-badge" style="min-width:140px;">
              <div class="status-badge-title">Confidence Score</div>
              <div class="status-badge-value">${report.confidence}%</div>
              <div class="status-badge-details">Analysis Certainty</div>
            </div>
          </div>
        </div>
      </div>
    `;

    const targetHTML = `
      <div class="report-card">
        <div class="section-title">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="12" cy="12" r="10"></circle>
            <polyline points="12 6 12 12 16 14"></polyline>
          </svg>
          Scan Information
        </div>
        <div class="info-grid">
          <div class="info-item">
            <div class="info-label">Scan Type</div>
            <div class="info-value">${report.type === 'url' ? 'URL Scan' : 'Email Scan'}</div>
          </div>
          <div class="info-item">
            <div class="info-label">Target</div>
            <div class="info-value" style="font-family: monospace; word-break: break-all;">
              ${this.escapeHtml(this.getDisplayTarget(report))}
            </div>
          </div>
          <div class="info-item">
            <div class="info-label">Scan Date</div>
            <div class="info-value">${report.date}</div>
          </div>
          <div class="info-item">
            <div class="info-label">Scan Time</div>
            <div class="info-value">${report.time}</div>
          </div>
        </div>
      </div>
    `;

    // Build a clear, type-specific header so users immediately see target + scan type
    let headerTitle = 'Scan Report';
    let headerLabel = '';
    const safeTarget = this.escapeHtml(this.getDisplayTarget(report));
    let headerValueHTML = `<strong>${safeTarget}</strong>`;

    if ((report.type || '').toString().toLowerCase().includes('email')) {
      headerTitle = 'Email Scan Report';
      headerLabel = 'Scanned Email';
      headerValueHTML = `<div style="font-family: Inter, system-ui, monospace; word-break: break-all;"><strong>${safeTarget}</strong></div>`;
    } else if (report.type === 'url') {
      headerTitle = 'URL Scan Report';
      headerLabel = 'Scanned URL';
      headerValueHTML = `<div style="font-family: Inter, system-ui, monospace; word-break: break-all;"><strong>${safeTarget}</strong></div>`;
    }

    const headerHTML = `
      <div class="report-header">
        <div>
          <div class="report-title">${headerTitle}</div>
          <div style="color: var(--text-muted); margin-top: 0.35rem;">${report.date} at ${report.time}</div>
          ${headerLabel ? `<div style="margin-top:0.45rem; font-size:0.9rem; color:var(--text-muted);">${headerLabel}</div>` : ''}
          <div style="margin-top:0.25rem;">${headerValueHTML}</div>
        </div>
        <div class="report-actions">
          <button class="btn-report btn-report-primary" id="btn-print-report">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <polyline points="6 9 6 2 18 2 18 9"></polyline>
              <path d="M6 18H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"></path>
              <rect x="6" y="14" width="12" height="8"></rect>
            </svg>
            Print Report
          </button>
          <button class="btn-report btn-report-primary" id="btn-save-pdf">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
              <polyline points="7 10 12 15 17 10"></polyline>
              <line x1="12" y1="15" x2="12" y2="3"></line>
            </svg>
            Save as PDF
          </button>
        </div>
      </div>
    `;

    const summaryHTML = `
      <div class="report-card">
        <div class="section-title">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>
          </svg>
          Summary
        </div>
        <div class="summary-box">
          <strong>${report.threat === 'safe' ? '✓ Safe' : report.threat === 'suspicious' ? '⚠ Warning' : '✕ Malicious'}</strong>
          <p>${this.escapeHtml(report.summary || 'No summary available')}</p>
        </div>
      </div>
    `;

    contentDiv.innerHTML = headerHTML + statusHTML + targetHTML + indicatorsHTML + issuesHTML + summaryHTML;
  }

  setupActionButtons() {
    const printBtn = document.getElementById('btn-print-report');
    const pdfBtn = document.getElementById('btn-save-pdf');

    if (printBtn) {
      printBtn.addEventListener('click', () => this.printReport());
    }

    if (pdfBtn) {
      pdfBtn.addEventListener('click', () => this.downloadPDF());
    }
  }

  printReport() {
    if (!this.currentReport) {
      this.showNotification('No report loaded', 'error');
      return;
    }

    window.print();
  }

  downloadPDF() {
    if (!this.currentReport) {
      this.showNotification('No report loaded', 'error');
      return;
    }

    const report = this.currentReport;
    const date = new Date();

    // Generate HTML content for PDF
    const htmlContent = this.generatePDFContent(report);

    // Create blob and download
    const blob = new Blob([htmlContent], { type: 'text/html' });
    const url = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;

    // Generate filename with timestamp
    const filename = `PhishNet_Report_${report.type}_${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')}.html`;
    link.download = filename;

    document.body.appendChild(link);
    link.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(link);

    this.showNotification('Report downloaded successfully!', 'success');
  }

  generatePDFContent(report) {
    const threatBgColor = report.threat === 'safe' ? '#00FF88' : 
                         report.threat === 'suspicious' ? '#FFC107' : '#FF4D4D';
    const threatTextColor = report.threat === 'safe' ? '#000' : 
                           report.threat === 'suspicious' ? '#000' : '#FFF';

    const indicatorsHTML = (report.indicators || []).map(indicator => {
      return `<li style="margin-bottom: 12px; padding: 10px; background: rgba(11, 99, 217, 0.1); border-left: 3px solid #0B63D9; border-radius: 4px;">
        <strong style="display: block; color: #333; margin-bottom: 4px;">${this.escapeHtml(indicator)}</strong>
      </li>`;
    }).join('');

    const issuesHTML = (report.issues || []).map(issue => {
      return `<li style="margin-bottom: 10px; color: #333;">${this.escapeHtml(issue)}</li>`;
    }).join('');

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
    .logo {
      font-size: 28px;
      font-weight: 700;
      color: #0B63D9;
      margin-bottom: 10px;
    }
    h1 {
      font-size: 24px;
      color: #333;
      margin-bottom: 10px;
    }
    h2 {
      font-size: 18px;
      color: #333;
      margin: 20px 0 15px 0;
      border-bottom: 2px solid #0B63D9;
      padding-bottom: 10px;
    }
    .status-section {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 20px;
      margin: 20px 0;
    }
    .status-box {
      padding: 20px;
      background: #f9f9f9;
      border-left: 4px solid #0B63D9;
      border-radius: 4px;
    }
    .status-label {
      font-size: 12px;
      color: #666;
      margin-bottom: 10px;
      font-weight: 600;
      text-transform: uppercase;
    }
    .status-value {
      font-size: 24px;
      font-weight: 700;
      color: ${threatBgColor};
      margin-bottom: 10px;
    }
    .badge {
      display: inline-block;
      padding: 6px 12px;
      border-radius: 20px;
      font-size: 12px;
      font-weight: 600;
      margin: 10px 0;
      background: ${threatBgColor};
      color: ${threatTextColor};
    }
    .info-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 20px;
      margin: 20px 0;
    }
    .info-item {
      padding: 12px;
      background: #f9f9f9;
      border-left: 3px solid #0B63D9;
      border-radius: 4px;
    }
    .info-label {
      font-size: 12px;
      color: #666;
      margin-bottom: 5px;
      font-weight: 600;
      text-transform: uppercase;
    }
    .info-value {
      font-size: 14px;
      color: #333;
      font-weight: 600;
      word-break: break-all;
    }
    ul {
      list-style: none;
      padding: 0;
      margin: 15px 0;
    }
    .summary-box {
      padding: 15px;
      background: #f0f7ff;
      border-left: 4px solid #0B63D9;
      border-radius: 4px;
      margin: 20px 0;
    }
    .summary-box strong {
      display: block;
      margin-bottom: 10px;
      color: #0B63D9;
    }
    .footer {
      text-align: center;
      margin-top: 40px;
      padding-top: 20px;
      border-top: 1px solid #eee;
      color: #999;
      font-size: 12px;
    }
    @media print {
      body { background: white; padding: 0; }
      .container { box-shadow: none; }
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="logo">PhishNet</div>
      <h1>Security Scan Report</h1>
      <p style="color: #999; margin: 10px 0 0 0;">Generated on ${report.date} at ${report.time}</p>
    </div>

    <h2>Scan Status</h2>
    <div class="status-section">
      <div class="status-box">
          <div class="status-label">Threat Assessment</div>
          <div class="status-value">${(report.threat||'').toUpperCase()}</div>
          <div class="badge">${(report.threat||'').toUpperCase()}</div>
        </div>
      <div class="status-box">
        <div class="status-label">Confidence Score</div>
        <div class="status-value">${report.confidence}%</div>
        <div style="color: #666; font-size: 12px;">Analysis Certainty</div>
      </div>
    </div>

    <h2>Scan Information</h2>
    <div class="info-grid">
      <div class="info-item">
        <div class="info-label">Scan Type</div>
        <div class="info-value">${report.type === 'url' ? 'URL Scan' : 'Email Scan'}</div>
      </div>
      <div class="info-item">
        <div class="info-label">Risk Level</div>
        <div class="info-value">${this.formatRisk(report.riskLevel) || 'Unknown'}</div>
      </div>
      <div class="info-item">
        <div class="info-label">Target</div>
        <div class="info-value">${this.escapeHtml(this.getDisplayTarget(report))}</div>
      </div>
      <div class="info-item">
        <div class="info-label">Scan Date</div>
        <div class="info-value">${report.date} at ${report.time}</div>
      </div>
    </div>

    <h2>Threat Indicators</h2>
    <ul>
      ${indicatorsHTML}
    </ul>

    <h2>Detected Issues</h2>
    <ul>
      ${issuesHTML}
    </ul>

    <h2>Summary</h2>
    <div class="summary-box">
      <strong>${report.threat === 'safe' ? '✓ Safe' : report.threat === 'suspicious' ? '⚠ Warning' : '✕ Malicious'}</strong>
      <p>${this.escapeHtml(report.summary || '')}</p>
    </div>

    <div class="footer">
      <p>PhishNet Security Report | Generated on ${new Date().toLocaleString()}</p>
      <p>This report is confidential and intended for authorized use only.</p>
    </div>
  </div>

  <script>
    window.addEventListener('load', function() {
      setTimeout(function() {
        window.print();
      }, 500);
    });
  </script>
</body>
</html>`;
  }

  showEmptyState(message) {
    const contentDiv = document.getElementById('report-content');
    contentDiv.innerHTML = `
      <div class="empty-state">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <circle cx="12" cy="12" r="10"></circle>
          <line x1="12" y1="8" x2="12" y2="12"></line>
          <line x1="12" y1="16" x2="12.01" y2="16"></line>
        </svg>
        <h2>Report Not Found</h2>
        <p>${message}</p>
        <a href="dashboard.html">Return to Dashboard</a>
      </div>
    `;
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
      z-index: 9999;
      animation: slideIn 0.3s ease-out;
    `;
    notification.textContent = message;
    document.body.appendChild(notification);

    setTimeout(function() {
      notification.style.animation = 'slideOut 0.3s ease-out';
      setTimeout(function() { notification.remove(); }, 300);
    }, 3000);
  }

  escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    new ReportViewer();
  });
} else {
  new ReportViewer();
}
