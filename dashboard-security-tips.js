(function(){
  // Helper to create tip element
  function createTipEl(tip) {
    const container = document.createElement('div');
    container.className = 'security-tip-item';
    container.style.display = 'flex';
    container.style.alignItems = 'center';
    container.style.justifyContent = 'flex-start';
    container.style.gap = '0.75rem';
    container.style.padding = '0.6rem';
    container.style.borderRadius = '8px';
    container.style.background = 'rgba(255,255,255,0.02)';
    container.style.minHeight = '48px';

    const iconWrap = document.createElement('div');
    iconWrap.style.width = '40px';
    iconWrap.style.height = '40px';
    iconWrap.style.display = 'flex';
    iconWrap.style.alignItems = 'center';
    iconWrap.style.justifyContent = 'center';
    iconWrap.style.flex = '0 0 40px';
    iconWrap.style.borderRadius = '8px';

    const txt = document.createElement('div');
    txt.style.flex = '1 1 auto';
    txt.style.color = '#FFFFFF';
    txt.style.fontSize = '0.95rem';
    txt.textContent = tip.message;

    // icon selection
    let svg = null;
    if (tip.type === 'warning') {
      iconWrap.style.background = 'linear-gradient(90deg,#ffecd1,#ffd6b0)';
      svg = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#A64A00" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>';
    } else if (tip.type === 'info') {
      iconWrap.style.background = 'linear-gradient(90deg,#e8f0ff,#d6e7ff)';
      svg = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#094F9E" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>';
    } else if (tip.type === 'success') {
      iconWrap.style.background = 'linear-gradient(90deg,#e8fff0,#d6ffe6)';
      svg = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#0B8A3E" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>';
    } else {
      iconWrap.style.background = 'rgba(255,255,255,0.03)';
      svg = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#999" stroke-width="2"><circle cx="12" cy="12" r="10"/></svg>';
    }

    iconWrap.innerHTML = svg;
    container.appendChild(iconWrap);
    container.appendChild(txt);

    return container;
  }

  async function loadTips() {
    const listEl = document.getElementById('security-tips-list');
    if (!listEl) return;

    // Clear placeholder
    listEl.innerHTML = '<div style="color:#AAAAAA">Loading security tips…</div>';

    try {
      const token = localStorage.getItem('token');
      const headers = token ? { 'Authorization': `Bearer ${token}` } : {};

      const res = await fetch(getApiUrl(window.API_CONFIG.api.endpoints.dashboard.securityTips), { headers });
      if (!res.ok) {
        listEl.innerHTML = '<div style="color:#FFB3B3">Unable to load tips</div>';
        return;
      }

      const data = await res.json();
      if (!data || !Array.isArray(data.tips)) {
        listEl.innerHTML = '<div style="color:#AAAAAA">No tips available</div>';
        return;
      }

      // Render up to 3 tips
      listEl.innerHTML = '';
      const tips = data.tips.slice(0,3);
      tips.forEach(tip => {
        const el = createTipEl(tip);
        listEl.appendChild(el);
      });

      if (tips.length === 0) {
        const el = document.createElement('div');
        el.style.color = '#AAAAAA';
        el.textContent = 'No recommendations at this time.';
        listEl.appendChild(el);
      }
    } catch (err) {
      listEl.innerHTML = '<div style="color:#FFB3B3">Error loading tips</div>';
      console.error('Failed to load security tips:', err);
    }
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
