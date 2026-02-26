(function(){
  // Type config
  const TYPE_CONFIG = {
    warning: { label: 'Warning', color: '#FFC107', icon: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>' },
    info:    { label: 'Tip', color: '#00B7D9', icon: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>' },
    success: { label: 'PhishNet', color: '#00FF88', icon: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>' },
  };

  function createTipEl(tip) {
    const cfg = TYPE_CONFIG[tip.type] || TYPE_CONFIG.info;
    const el = document.createElement('div');
    el.className = 'dash-tip-card';
    el.style.borderLeftColor = cfg.color;
    el.innerHTML = `
      <div class="dash-tip-top">
        <span class="dash-tip-icon" style="color:${cfg.color}">${cfg.icon}</span>
        <span class="dash-tip-label" style="color:${cfg.color}">${cfg.label}</span>
      </div>
      <p class="dash-tip-text">${tip.message}</p>
    `;
    return el;
  }

  // Built-in security tips relevant to PhishNet's detection capabilities
  const BUILT_IN_TIPS = [
    // Phishing awareness
    { type: 'warning', message: 'Always verify the sender\'s email address — phishers often use look-alike domains (e.g. paypa1.com instead of paypal.com).' },
    { type: 'warning', message: 'Never enter passwords on HTTP sites. Legitimate services always use HTTPS with a valid certificate.' },
    { type: 'warning', message: 'Be cautious of urgent messages threatening account suspension — this is a common social engineering tactic.' },
    { type: 'info', message: 'Hover over links before clicking to preview the actual URL. URL shorteners can hide malicious destinations.' },
    { type: 'info', message: 'Typosquatting attacks use misspelled brand names (e.g. googlr.com). Always double-check the domain spelling.' },
    { type: 'warning', message: 'Domains registered less than 30 days ago with login forms are high-risk — phishing sites are typically short-lived.' },
    // Browser & extension tips
    { type: 'success', message: 'PhishNet scans every URL across 7 detection layers including Google Safe Browsing, VirusTotal, and ML analysis.' },
    { type: 'info', message: 'Keep PhishNet protection enabled at all times. You can manage it from the extension popup.' },
    { type: 'success', message: 'PhishNet detects homograph attacks — Unicode characters that look identical to Latin letters (e.g. аpple.com using Cyrillic "а").' },
    // Password & account security
    { type: 'info', message: 'Use a unique password for every account. A password manager makes this easy and secure.' },
    { type: 'info', message: 'Enable two-factor authentication (2FA) on all important accounts — it blocks 99% of automated attacks.' },
    { type: 'warning', message: 'If a site asks you to disable your browser\'s security warnings, it\'s almost certainly malicious.' },
    // SSL & certificate awareness
    { type: 'warning', message: 'Self-signed or expired SSL certificates are a red flag. PhishNet checks certificate validity on every visit.' },
    { type: 'info', message: 'Free certificates (Let\'s Encrypt) on newly registered domains with login forms are a common phishing indicator.' },
    { type: 'info', message: 'Check the padlock icon in your browser\'s address bar — click it to verify the site\'s certificate details.' },
    // General web safety
    { type: 'warning', message: 'Avoid downloading files from URLs flagged by PhishNet — they may contain malware or credential-stealing scripts.' },
    { type: 'info', message: 'Bookmark important sites (bank, email) and use bookmarks to navigate — never follow links from unsolicited messages.' },
    { type: 'success', message: 'PhishNet\'s ML model (BERT) can detect zero-day phishing pages that aren\'t yet in any threat database.' },
  ];

  // Pick 3 random non-repeating tips
  function getRandomTips(count) {
    const shuffled = [...BUILT_IN_TIPS].sort(() => Math.random() - 0.5);
    return shuffled.slice(0, count);
  }

  async function loadTips() {
    const listEl = document.getElementById('security-tips-list');
    if (!listEl) return;

    listEl.innerHTML = '<div style="color:#AAAAAA">Loading security tips…</div>';

    let tips = null;

    // Try API first
    try {
      const token = localStorage.getItem('token');
      const headers = token ? { 'Authorization': `Bearer ${token}` } : {};
      const res = await fetch(getApiUrl(window.API_CONFIG.api.endpoints.dashboard.securityTips), { headers });
      if (res.ok) {
        const data = await res.json();
        if (data && Array.isArray(data.tips) && data.tips.length > 0) {
          tips = data.tips.slice(0, 3);
        }
      }
    } catch (err) {
      // API unavailable — fall through to built-in tips
    }

    // Fallback to built-in tips
    if (!tips || tips.length === 0) {
      tips = getRandomTips(3);
    }

    listEl.innerHTML = '';
    tips.forEach(tip => {
      const el = createTipEl(tip);
      listEl.appendChild(el);
    });
  }

  function wireButtons() {
    const learnBtn = document.getElementById('learn-security-btn');
    if (learnBtn) learnBtn.addEventListener('click', () => { window.location.href = 'blog.html'; });
  }

  document.addEventListener('DOMContentLoaded', () => {
    wireButtons();
    loadTips();
  });
})();
