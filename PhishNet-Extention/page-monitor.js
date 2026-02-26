// Page Monitor: content-hash invalidation, form submission detection, DOM mutation watching
// Runs on all HTTP/HTTPS pages to provide cache invalidation signals to background.js
(function () {
  'use strict';

  // ════════════════════════════════════════════════════════════════
  //  FNV-1a hash — fast, non-cryptographic 32-bit fingerprint
  // ════════════════════════════════════════════════════════════════
  function fnv1a(str) {
    let h = 0x811c9dc5;
    for (let i = 0; i < str.length; i++) {
      h ^= str.charCodeAt(i);
      h = Math.imul(h, 0x01000193) >>> 0;
    }
    return h.toString(16).padStart(8, '0');
  }

  // ════════════════════════════════════════════════════════════════
  //  Content Hash Computation
  //  Fingerprints: visible text (first 10 KB), form structure,
  //  external scripts, hidden credential forms, iframe sources
  // ════════════════════════════════════════════════════════════════
  function computeContentHash() {
    try {
      // 1. Visible text (capped for performance)
      const text = (document.body?.innerText || '').substring(0, 10000).trim();

      // 2. Form structure fingerprint
      const forms = document.querySelectorAll('form');
      const formFP = Array.from(forms).map(f => {
        const inputs = f.querySelectorAll('input, select, textarea');
        const types = Array.from(inputs)
          .map(i => (i.type || 'text').toLowerCase())
          .sort()
          .join(',');
        return `${f.action || '_self'}|${(f.method || 'get').toLowerCase()}|${types}`;
      }).join('||');

      // 3. External script fingerprint
      const scriptSrcs = Array.from(document.querySelectorAll('script[src]'))
        .map(s => s.src)
        .sort()
        .join('|');

      // 4. Hidden credential forms (phishing red flag)
      const hiddenPwdInputs = document.querySelectorAll(
        '[style*="display:none"] input[type="password"], ' +
        '[style*="display: none"] input[type="password"], ' +
        '[hidden] input[type="password"], ' +
        '.hidden input[type="password"], ' +
        'input[type="password"][style*="display:none"], ' +
        'input[type="password"][style*="opacity:0"]'
      );

      // 5. Iframes (cross-origin phishing overlays)
      const iframeSrcs = Array.from(document.querySelectorAll('iframe[src]'))
        .map(f => {
          try { return new URL(f.src).hostname; } catch (_) { return f.src; }
        })
        .sort()
        .join('|');

      const raw = [
        text,
        'FORMS:' + formFP,
        'SCRIPTS:' + scriptSrcs,
        'HIDDEN_PWD:' + hiddenPwdInputs.length,
        'IFRAMES:' + iframeSrcs
      ].join('\n');

      return fnv1a(raw);
    } catch (_) {
      return null;
    }
  }

  // ════════════════════════════════════════════════════════════════
  //  1. Send initial content hash after page load
  // ════════════════════════════════════════════════════════════════
  let currentHash = null;

  function sendContentHash() {
    currentHash = computeContentHash();
    if (!currentHash) return;
    try {
      chrome.runtime.sendMessage({
        type: 'phishnet.content-hash',
        url: location.href,
        hash: currentHash
      }, () => { if (chrome.runtime.lastError) { /* background not ready */ } });
    } catch (_) { /* extension context invalidated */ }
  }

  if (document.readyState === 'complete') {
    sendContentHash();
  } else {
    window.addEventListener('load', sendContentHash, { once: true });
  }

  // ════════════════════════════════════════════════════════════════
  //  2. DOM Mutation Observer — detect late-injected phishing content
  //     Watches for: forms, password inputs, scripts, iframes
  //     Debounced 2 s to avoid excessive hash recomputation
  // ════════════════════════════════════════════════════════════════
  const SECURITY_TAGS = new Set(['FORM', 'INPUT', 'SCRIPT', 'IFRAME', 'OBJECT', 'EMBED']);
  let hashTimer = null;

  function scheduleHashRecheck() {
    if (hashTimer) return; // already scheduled
    hashTimer = setTimeout(() => {
      hashTimer = null;
      const newHash = computeContentHash();
      if (newHash && currentHash && newHash !== currentHash) {
        console.log('[PhishNet Monitor] Content hash changed:', currentHash, '→', newHash);
        try {
          chrome.runtime.sendMessage({
            type: 'phishnet.content-changed',
            url: location.href,
            oldHash: currentHash,
            newHash: newHash
          }, () => { if (chrome.runtime.lastError) {} });
        } catch (_) {}
        currentHash = newHash;
      } else if (newHash) {
        currentHash = newHash;
      }
    }, 2000);
  }

  const observer = new MutationObserver((mutations) => {
    for (const m of mutations) {
      if (m.type !== 'childList' || m.addedNodes.length === 0) continue;
      for (const node of m.addedNodes) {
        if (node.nodeType !== 1) continue; // Element nodes only
        if (SECURITY_TAGS.has(node.tagName)) {
          scheduleHashRecheck();
          return; // one trigger is enough
        }
        // Check descendants of the added subtree
        if (node.querySelector &&
            node.querySelector('form, input[type="password"], script, iframe, object, embed')) {
          scheduleHashRecheck();
          return;
        }
      }
    }
  });

  // Start observing after DOM is ready
  if (document.documentElement) {
    observer.observe(document.documentElement, { childList: true, subtree: true });
  }

  // ════════════════════════════════════════════════════════════════
  //  3. Form Submission Monitoring
  //     Captures credential submissions (forms with password/email
  //     fields) and notifies background.js to invalidate cache
  //     and re-scan the action URL.
  // ════════════════════════════════════════════════════════════════
  document.addEventListener('submit', (event) => {
    const form = event.target;
    if (!(form instanceof HTMLFormElement)) return;

    // Resolve action URL
    let actionUrl;
    try {
      actionUrl = new URL(form.action || '', location.href).href;
    } catch (_) {
      actionUrl = location.href;
    }

    // Detect credential fields
    const pwdFields = form.querySelectorAll('input[type="password"]');
    const idFields  = form.querySelectorAll(
      'input[type="email"], input[name*="email" i], ' +
      'input[name*="user" i], input[name*="login" i], ' +
      'input[name*="account" i], input[autocomplete="username"]'
    );
    const hasCredentials = pwdFields.length > 0 || idFields.length > 0;

    try {
      chrome.runtime.sendMessage({
        type: 'phishnet.form-submit',
        url: location.href,
        actionUrl,
        hasCredentials,
        method: (form.method || 'GET').toUpperCase(),
        fieldCount: form.querySelectorAll('input, select, textarea').length,
        passwordFieldCount: pwdFields.length
      }, () => { if (chrome.runtime.lastError) {} });
    } catch (_) {}
  }, true); // capture phase — fires even if default is prevented

  // ════════════════════════════════════════════════════════════════
  //  4. Client-side redirect detection
  //     Detect <meta http-equiv="refresh"> tags
  //     Server/client redirects are caught by webNavigation.onCommitted
  //     SPA pushState/replaceState are caught via popstate + periodic URL check
  // ════════════════════════════════════════════════════════════════

  // Check for meta refresh tags
  function checkMetaRefresh() {
    const metas = document.querySelectorAll('meta[http-equiv="refresh"]');
    for (const meta of metas) {
      const content = meta.getAttribute('content') || '';
      // Format: "5;url=http://evil.com" or "0; URL=..."
      const match = content.match(/url\s*=\s*['"]?([^'";\s]+)/i);
      if (match) {
        let targetUrl;
        try { targetUrl = new URL(match[1], location.href).href; } catch (_) { continue; }
        console.log('[PhishNet Monitor] Meta refresh redirect detected →', targetUrl);
        try {
          chrome.runtime.sendMessage({
            type: 'phishnet.meta-redirect',
            sourceUrl: location.href,
            targetUrl
          }, () => { if (chrome.runtime.lastError) {} });
        } catch (_) {}
      }
    }
  }

  // Check after DOM is parsed
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', checkMetaRefresh, { once: true });
  } else {
    checkMetaRefresh();
  }

  // Detect SPA navigation via popstate + periodic URL polling
  let lastKnownUrl = location.href;

  function checkUrlChange() {
    const currentUrl = location.href;
    if (currentUrl !== lastKnownUrl) {
      const prevUrl = lastKnownUrl;
      lastKnownUrl = currentUrl;
      try {
        chrome.runtime.sendMessage({
          type: 'phishnet.spa-navigation',
          sourceUrl: prevUrl,
          targetUrl: currentUrl,
          method: 'url-change'
        }, () => { if (chrome.runtime.lastError) {} });
      } catch (_) {}
    }
  }

  // popstate fires on back/forward and some SPA navigations
  window.addEventListener('popstate', () => setTimeout(checkUrlChange, 50));

  // Poll URL every 3s to catch pushState/replaceState (isolated world can't monkey-patch them)
  setInterval(checkUrlChange, 3000);

})();
