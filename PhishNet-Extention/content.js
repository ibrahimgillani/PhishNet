// Content script: bridges website localStorage auth token to extension chrome.storage.local
// This runs on PhishNet website pages and forwards the login token to the background service worker,
// so that background scans include the auth token and get saved to MongoDB.
(function () {
  'use strict';

  const SYNC_MSG_TYPE = 'phishnet.sync-token';

  // ---- 1. Sync token from localStorage on every page load ----
  function syncTokenFromLocalStorage() {
    const token = localStorage.getItem('token');
    if (token) {
      chrome.runtime.sendMessage({ type: SYNC_MSG_TYPE, token }, () => {
        if (chrome.runtime.lastError) {
          console.log('[PhishNet Content] Background not ready:', chrome.runtime.lastError.message);
        } else {
          console.log('[PhishNet Content] Token synced from localStorage');
        }
      });
    }
  }

  // Run once at document_idle
  syncTokenFromLocalStorage();

  // ---- 2. Listen for the custom event dispatched by app.js syncTokenToExtension() ----
  window.addEventListener('phishnet-token-sync', (event) => {
    const token = event.detail?.token;
    chrome.runtime.sendMessage({ type: SYNC_MSG_TYPE, token: token || null }, () => {
      if (chrome.runtime.lastError) {
        console.log('[PhishNet Content] Background not ready:', chrome.runtime.lastError.message);
      } else {
        console.log('[PhishNet Content] Token synced via custom event');
      }
    });
  });

  // ---- 3. Listen for cross-tab storage changes (login/logout in another tab) ----
  window.addEventListener('storage', (event) => {
    if (event.key === 'token') {
      chrome.runtime.sendMessage({ type: SYNC_MSG_TYPE, token: event.newValue || null }, () => {
        if (chrome.runtime.lastError) return;
        console.log('[PhishNet Content] Token updated via storage event');
      });
    }
  });

  // ---- 4. Respond to token requests from background.js ----
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message?.type === 'phishnet.request-token') {
      const token = localStorage.getItem('token') || null;
      sendResponse({ token });
    }
  });
})();
