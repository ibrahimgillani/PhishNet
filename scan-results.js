// Externalized script for scan-results.html to comply with CSP (no inline scripts)
(function(){
  const STORAGE_KEY = 'scanHistory';

  function ensureIds(list) {
    const now = Date.now();
    return list.map((scan, idx) => {
      if (!scan || !scan.id) {
        return { ...scan, id: `local-${now + idx}` };
      }
      return { ...scan, id: String(scan.id) };
    });
  }

  function sanitizeValue(val) {
    if (val === undefined || val === null) return null;
    if (typeof val === 'string') {
      const s = val.trim();
      if (s === '' || s.toLowerCase() === 'undefined' || s.toLowerCase() === 'null') return null;
      return s;
    }
    return val;
  }

  function escapeHtml(text) {
    if (!text) return '';
    const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
    return String(text).replace(/[&<>"']/g, (ch) => map[ch] || ch);
  }

  function showDeleteConfirm(targetLabel) {
    return new Promise((resolve) => {
      const existing = document.querySelector('.delete-confirm-overlay');
      if (existing) existing.remove();

      const overlay = document.createElement('div');
      overlay.className = 'delete-confirm-overlay';
      overlay.innerHTML = `
        <div class="delete-confirm-modal">
          <div class="delete-confirm-header">
            <div class="delete-confirm-icon">!</div>
            <div>
              <h3 class="delete-confirm-title">Delete this report?</h3>
              <p class="delete-confirm-subtext">This action cannot be undone.</p>
            </div>
          </div>
          <div class="delete-confirm-body">
            <p class="delete-confirm-message">You are about to remove <span class="delete-confirm-highlight">${escapeHtml(targetLabel)}</span> from your reports.</p>
            <p class="delete-confirm-note">If you need this later, export or screenshot before deleting.</p>
          </div>
          <div class="delete-confirm-actions">
            <button type="button" class="modal-btn secondary">Cancel</button>
            <button type="button" class="modal-btn danger">Yes, delete</button>
          </div>
        </div>
      `;

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

  function mapThreatLevel(threatLevel) {
    if (threatLevel === 'safe') return 'safe';
    if (threatLevel === 'low' || threatLevel === 'medium') return 'suspicious';
    if (threatLevel === 'high' || threatLevel === 'critical') return 'malicious';
    return 'safe';
  }

  async function loadScans() {
    const token = localStorage.getItem('token');
    if (token) {
      try {
        const resp = await fetch(getApiUrlWithParams(window.API_CONFIG.api.endpoints.users.history, { limit: 200 }), { headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' } });
        if (resp.ok) {
          const data = await resp.json();
          if (data.success && Array.isArray(data.data.history)) {
            const mapped = data.data.history.map(item => {
              const rawThreat = item.threatLevel || item.threat || item.status || (item.isSafe === true ? 'safe' : (item.isSafe === false ? 'malicious' : null));
              const normalized = rawThreat && (['safe','suspicious','malicious'].includes(String(rawThreat).toLowerCase()) )
                ? String(rawThreat).toLowerCase()
                : mapThreatLevel(rawThreat);

              return ({
                id: String(item._id),
                target: (String(item.scanType || '').toLowerCase().indexOf('email') !== -1) ? (item.senderEmail || item.email || item.url || '') : (item.url || item.value || ''),
                type: item.scanType || ((item.url||'').includes('@') ? 'email' : 'url'),
                result: normalized || (item.isSafe === true ? 'safe' : (item.isSafe === false ? 'malicious' : 'safe')),
                confidence: item.confidence || null,
                date: item.checkedAt ? new Date(item.checkedAt).toLocaleDateString() : '',
                time: item.checkedAt ? new Date(item.checkedAt).toLocaleTimeString() : ''
              ,
                // Preserve original server record so the detailed viewer can use full fields
                raw: item
              });
            });
            return mapped;
          }
        }
        // If unauthorized, clear token and cached scans to prevent data leaking between users
        if (resp && resp.status === 401) {
          console.warn('[scan-results] Unauthorized - clearing token and cached scan data');
          localStorage.removeItem('token');
          localStorage.removeItem('scanHistory');
          localStorage.removeItem('selectedScan');
          localStorage.removeItem('selectedScanId');
          if (window.scanManager) window.scanManager.scanHistory = [];
          return [];
        }
      } catch (err) {
        console.warn('Failed to load server history, falling back to localStorage', err);
      }
    }

    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored) {
      try {
        return JSON.parse(stored);
      } catch (e) {
        console.warn('Failed to parse stored scans, returning empty list.');
        return [];
      }
    }
    return [];
  }

  let scans = [];
  (async () => {
    scans = ensureIds(await loadScans());
    try { localStorage.setItem(STORAGE_KEY, JSON.stringify(scans)); } catch(e){}
    renderTable();
  })();

  function saveScans() {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(scans));
  }

  function renderTable() {
    const tbody = document.querySelector("#scan-results-table tbody");
    if (!tbody) return;
    tbody.innerHTML = "";

    if (!scans.length) {
      tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; padding: 30px;">No scan results yet.</td></tr>';
      return;
    }

    scans.forEach((scan) => {
      const tr = document.createElement("tr");
      const threat = (scan.threat || scan.result || "").toLowerCase();
      const resultClass = threat === "safe" ? "result-safe" : threat === "suspicious" ? "result-suspicious" : threat === "malicious" ? "result-malicious" : "";

      const viewBtn = document.createElement("button");
      viewBtn.className = "action-btn view-btn";
      viewBtn.dataset.action = "view";
      viewBtn.dataset.id = scan.id;
      viewBtn.title = "View detailed report";
      viewBtn.textContent = "View";

      const deleteBtn = document.createElement("button");
      deleteBtn.className = "action-btn delete-btn";
      deleteBtn.dataset.action = "delete";
      deleteBtn.dataset.id = scan.id;
      deleteBtn.title = "Delete this result";
      deleteBtn.textContent = "Delete";

      const extractEmail = (text) => { try { const m = String(text||'').match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i); return m ? m[0] : ''; } catch(e){return '';} };
      const displayTarget = String(scan.type || '').toLowerCase().includes('email') ? (scan.target || extractEmail(scan.value) || '') : (scan.target || scan.value || '');

      tr.innerHTML = `
        <td title="${displayTarget}">${displayTarget}</td>
        <td>${scan.type ? scan.type.toUpperCase() : ""}</td>
        <td class="${resultClass}">${scan.result || (scan.threat ? scan.threat.charAt(0).toUpperCase() + scan.threat.slice(1) : "")}</td>
        <td>${scan.confidence}%</td>
        <td>${scan.date ? scan.date + " " + (scan.time || "") : (scan.time || "")}</td>
        <td class="actions-cell"></td>
      `;

      const actionsCell = tr.querySelector(".actions-cell");
      actionsCell.appendChild(viewBtn);
      actionsCell.appendChild(deleteBtn);

      tbody.appendChild(tr);
    });
  }

  function viewReport(id) {
    const scan = scans.find((s) => String(s.id) === String(id));
    if (!scan) return;
    localStorage.setItem('selectedScanId', String(id));
    // If we have a preserved raw server record, store that for the detailed report page
    try {
      if (scan.raw) {
        // Normalize server record to include `id` and `timestamp` keys expected by report pages
        const raw = scan.raw;
        const detailed = Object.assign({}, raw, {
          id: String(raw._id || raw.id || scan.id),
          timestamp: raw.checkedAt ? new Date(raw.checkedAt).getTime() : (raw.timestamp || Date.now())
        });
        // sanitize common fields so literal 'undefined' strings don't show in UI
        try {
          detailed.summary = sanitizeValue(detailed.summary) || '';
          detailed.riskLevel = sanitizeValue(detailed.riskLevel) || sanitizeValue(detailed.risk) || null;
          if (detailed.indicators && Array.isArray(detailed.indicators)) {
            detailed.indicators = detailed.indicators.map(i => sanitizeValue(i)).filter(i => i !== null);
          }
          if (detailed.issues && Array.isArray(detailed.issues)) {
            detailed.issues = detailed.issues.map(i => sanitizeValue(i)).filter(i => i !== null);
          }
        } catch (e) {}
        localStorage.setItem('selectedScan', JSON.stringify(detailed));
      } else {
        localStorage.setItem('selectedScan', JSON.stringify(scan));
      }
    } catch (e) {
      localStorage.setItem('selectedScan', JSON.stringify(scan));
    }
    window.location.href = `reports.html?scanId=${id}`;
  }

  async function deleteReport(id) {
    const token = localStorage.getItem('token');
    const scan = scans.find((s) => String(s.id) === String(id));
    if (!scan) return;
    const label = String(scan.type || '').toLowerCase().includes('email') ? (scan.target || '') : (scan.target || scan.value || '');
    const confirmed = await showDeleteConfirm(label);
    if (!confirmed) return;

    if (token) {
      try {
        const resp = await fetch(`/api/scan/${id}`, { method: 'DELETE', headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' } });
        if (resp.ok) {
          const response = await fetch(getApiUrlWithParams(window.API_CONFIG.api.endpoints.users.history, { limit: 200 }), { headers: { 'Authorization': `Bearer ${token}` } });
          if (response.ok) {
            const data = await response.json();
            scans = (data.data && data.data.history) ? data.data.history.map((item, idx) => ({ id: String(item._id), target: (String(item.scanType || '').toLowerCase().indexOf('email') !== -1) ? (item.senderEmail || item.email || item.url || '') : (item.url || item.value || ''), type: item.scanType, result: mapThreatLevel(item.threatLevel), confidence: item.confidence, date: new Date(item.checkedAt).toLocaleDateString(), time: new Date(item.checkedAt).toLocaleTimeString(), raw: item })) : [];
            saveScans();
            renderTable();
            const storedSelected = localStorage.getItem('selectedScanId');
            if (storedSelected && String(storedSelected) === String(id)) {
              localStorage.removeItem('selectedScanId');
              localStorage.removeItem('selectedScan');
            }
            return;
          } else if (response.status === 401) {
            // Unauthorized - clear token and cached scans to avoid leaking previous user's data
            console.warn('[scan-results] Unauthorized after delete - clearing token and cached scan data');
            localStorage.removeItem('token');
            localStorage.removeItem('scanHistory');
            localStorage.removeItem('selectedScan');
            localStorage.removeItem('selectedScanId');
            scans = [];
            saveScans();
            renderTable();
            return;
          }
        }
      } catch (err) {
        console.warn('Server delete failed, falling back to local delete', err);
      }
    }

    scans = scans.filter((s) => String(s.id) !== String(id));
    saveScans();
    const storedSelected = localStorage.getItem('selectedScanId');
    if (storedSelected && storedSelected === String(id)) {
      localStorage.removeItem('selectedScanId');
      localStorage.removeItem('selectedScan');
    }
    renderTable();
  }

  function handleActionClick(event) {
    const action = event.target.getAttribute("data-action");
    const idAttr = event.target.getAttribute("data-id");
    if (!action || !idAttr) return;
    const id = idAttr;
    if (action === "view") {
      viewReport(id);
    } else if (action === "delete") {
      deleteReport(id);
    }
  }

  document.addEventListener("DOMContentLoaded", () => {
    renderTable();
    const tbody = document.querySelector("#scan-results-table tbody");
    if (tbody) tbody.addEventListener("click", handleActionClick);
  });

})();
