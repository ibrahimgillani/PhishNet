/**
 * PhishNet Email Scanner — Content Script for Gmail & Outlook
 * 
 * Injects "Scan with PhishNet" button when viewing emails.
 * Extracts email headers + body and sends to background.js for analysis.
 * Displays results in a floating overlay.
 * 
 * Supports:
 *   - Gmail (mail.google.com)
 *   - Outlook Web (outlook.live.com, outlook.office.com, outlook.office365.com)
 */

(function () {
  'use strict';

  // Prevent double-injection
  if (window.__phishnetEmailScanner) return;
  window.__phishnetEmailScanner = true;

  const PLATFORM = detectPlatform();
  if (!PLATFORM) return;

  console.log(`[PhishNet Email] Loaded on ${PLATFORM}`);

  // ════════════════════════════════════════════════════════════
  //  CONSTANTS
  // ════════════════════════════════════════════════════════════
  const BUTTON_ID = 'phishnet-scan-email-btn';
  const OVERLAY_ID = 'phishnet-email-overlay';
  const CHECK_INTERVAL_MS = 1500;   // poll for open email every 1.5s
  const DEBOUNCE_MS = 500;

  let lastInjectedKey = null;       // prevent re-injecting for same email
  let debounceTimer = null;

  // ════════════════════════════════════════════════════════════
  //  PLATFORM DETECTION
  // ════════════════════════════════════════════════════════════
  function detectPlatform() {
    const host = location.hostname;
    if (host === 'mail.google.com') return 'gmail';
    if (host.includes('outlook.live.com') ||
        host.includes('outlook.office.com') ||
        host.includes('outlook.office365.com')) return 'outlook';
    return null;
  }

  // ════════════════════════════════════════════════════════════
  //  INJECT STYLES
  // ════════════════════════════════════════════════════════════
  function injectStyles() {
    if (document.getElementById('phishnet-email-styles')) return;
    const style = document.createElement('style');
    style.id = 'phishnet-email-styles';
    style.textContent = `
      @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;600;700;900&family=Inter:wght@300;400;500;600;700&family=Roboto+Mono:wght@400;500&display=swap');

      /* ─── Scan Button ─── */
      #${BUTTON_ID} {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        padding: 8px 18px;
        border: none;
        border-radius: 6px;
        background: linear-gradient(135deg, #0B63D9 0%, #0077D9 100%);
        color: #ffffff;
        font-family: 'Inter', system-ui, -apple-system, sans-serif;
        font-size: 13px;
        font-weight: 600;
        cursor: pointer;
        box-shadow: 0 2px 6px rgba(11, 99, 217, 0.25);
        transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
        z-index: 99999;
        white-space: nowrap;
        line-height: 1;
        margin: 4px 6px;
      }
      #${BUTTON_ID}:hover {
        transform: translateY(-1px);
        box-shadow: 0 4px 12px rgba(11, 99, 217, 0.35);
        background: linear-gradient(135deg, #0050C0 0%, #0055BB 100%);
      }
      #${BUTTON_ID}:active {
        transform: translateY(0);
        box-shadow: 0 2px 4px rgba(11, 99, 217, 0.2);
      }
      #${BUTTON_ID}.scanning {
        pointer-events: none;
        opacity: 0.8;
      }
      @keyframes phishnet-spin {
        from { transform: rotate(0deg); }
        to { transform: rotate(360deg); }
      }
      #${BUTTON_ID} .phishnet-icon {
        width: 15px;
        height: 15px;
        display: inline-block;
        flex-shrink: 0;
      }
      #${BUTTON_ID} .phishnet-label {
        opacity: 1;
      }

      /* ─── Overlay Panel ─── */
      #${OVERLAY_ID} {
        position: fixed;
        top: 0; right: 0;
        width: 440px;
        max-width: 100vw;
        height: 100vh;
        background: #0B0B0B;
        color: #fff;
        z-index: 2147483647;
        font-family: 'Inter', system-ui, -apple-system, sans-serif;
        box-shadow: -6px 0 40px rgba(0,0,0,0.7), -1px 0 0 rgba(11,99,217,0.15);
        overflow-y: auto;
        overflow-x: hidden;
        transition: transform 0.35s cubic-bezier(0.16, 1, 0.3, 1);
        transform: translateX(100%);
        scrollbar-width: thin;
        scrollbar-color: rgba(11,99,217,0.3) transparent;
      }
      #${OVERLAY_ID}::-webkit-scrollbar { width: 5px; }
      #${OVERLAY_ID}::-webkit-scrollbar-track { background: transparent; }
      #${OVERLAY_ID}::-webkit-scrollbar-thumb { background: rgba(11,99,217,0.3); border-radius: 10px; }
      #${OVERLAY_ID}.visible {
        transform: translateX(0);
      }

      /* ─── Header Bar ─── */
      #${OVERLAY_ID} .pn-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 14px 20px;
        border-bottom: 1px solid rgba(255,255,255,0.06);
        position: sticky;
        top: 0;
        background: linear-gradient(180deg, #0B0B0B 0%, rgba(11,11,11,0.97) 100%);
        backdrop-filter: blur(12px);
        z-index: 2;
      }
      #${OVERLAY_ID} .pn-header-brand {
        display: flex;
        align-items: center;
        gap: 10px;
      }
      #${OVERLAY_ID} .pn-header-logo {
        width: 28px; height: 28px;
        background: linear-gradient(135deg, #0B63D9 0%, #00B7D9 100%);
        border-radius: 8px;
        display: flex;
        align-items: center;
        justify-content: center;
        box-shadow: 0 2px 8px rgba(11,99,217,0.3);
      }
      #${OVERLAY_ID} .pn-header-logo svg { width: 16px; height: 16px; }
      #${OVERLAY_ID} .pn-title {
        margin: 0;
        font-family: 'Orbitron', sans-serif;
        font-size: 14px;
        font-weight: 700;
        color: #fff;
        letter-spacing: 1.5px;
        text-transform: uppercase;
      }
      #${OVERLAY_ID} .pn-close {
        background: rgba(255,255,255,0.04);
        border: 1px solid rgba(255,255,255,0.06);
        color: #999;
        width: 32px; height: 32px;
        display: flex;
        align-items: center;
        justify-content: center;
        border-radius: 8px;
        cursor: pointer;
        font-size: 18px;
        transition: all 0.2s;
      }
      #${OVERLAY_ID} .pn-close:hover {
        background: rgba(255,255,255,0.08);
        color: #fff;
        border-color: rgba(255,255,255,0.12);
      }

      /* ─── Verdict Card ─── */
      #${OVERLAY_ID} .pn-verdict {
        margin: 16px 16px 0;
        padding: 20px;
        border-radius: 12px;
        position: relative;
        overflow: hidden;
        border: 1px solid rgba(255,255,255,0.04);
      }
      #${OVERLAY_ID} .pn-verdict::before {
        content: '';
        position: absolute;
        top: 0; left: 0; right: 0;
        height: 2px;
      }
      #${OVERLAY_ID} .pn-verdict.safe {
        background: linear-gradient(135deg, rgba(0,255,136,0.06), rgba(0,255,136,0.02));
      }
      #${OVERLAY_ID} .pn-verdict.safe::before {
        background: linear-gradient(90deg, #00FF88, #10B981);
      }
      #${OVERLAY_ID} .pn-verdict.caution {
        background: linear-gradient(135deg, rgba(255,193,7,0.06), rgba(255,193,7,0.02));
      }
      #${OVERLAY_ID} .pn-verdict.caution::before {
        background: linear-gradient(90deg, #FFC107, #F59E0B);
      }
      #${OVERLAY_ID} .pn-verdict.suspicious {
        background: linear-gradient(135deg, rgba(249,115,22,0.06), rgba(249,115,22,0.02));
      }
      #${OVERLAY_ID} .pn-verdict.suspicious::before {
        background: linear-gradient(90deg, #F97316, #FB923C);
      }
      #${OVERLAY_ID} .pn-verdict.malicious {
        background: linear-gradient(135deg, rgba(255,77,77,0.08), rgba(255,77,77,0.02));
      }
      #${OVERLAY_ID} .pn-verdict.malicious::before {
        background: linear-gradient(90deg, #FF4D4D, #EF4444);
      }
      #${OVERLAY_ID} .pn-verdict-top {
        display: flex;
        align-items: center;
        gap: 14px;
        margin-bottom: 12px;
      }
      #${OVERLAY_ID} .pn-verdict-icon {
        width: 48px; height: 48px;
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        flex-shrink: 0;
      }
      #${OVERLAY_ID} .pn-verdict-icon svg { width: 24px; height: 24px; }
      #${OVERLAY_ID} .pn-verdict.safe .pn-verdict-icon { background: rgba(0,255,136,0.1); border: 1px solid rgba(0,255,136,0.2); }
      #${OVERLAY_ID} .pn-verdict.safe .pn-verdict-icon svg { color: #00FF88; }
      #${OVERLAY_ID} .pn-verdict.caution .pn-verdict-icon { background: rgba(255,193,7,0.1); border: 1px solid rgba(255,193,7,0.2); }
      #${OVERLAY_ID} .pn-verdict.caution .pn-verdict-icon svg { color: #FFC107; }
      #${OVERLAY_ID} .pn-verdict.suspicious .pn-verdict-icon { background: rgba(249,115,22,0.1); border: 1px solid rgba(249,115,22,0.2); }
      #${OVERLAY_ID} .pn-verdict.suspicious .pn-verdict-icon svg { color: #F97316; }
      #${OVERLAY_ID} .pn-verdict.malicious .pn-verdict-icon { background: rgba(255,77,77,0.1); border: 1px solid rgba(255,77,77,0.2); }
      #${OVERLAY_ID} .pn-verdict.malicious .pn-verdict-icon svg { color: #FF4D4D; }
      #${OVERLAY_ID} .pn-verdict-text h3 {
        margin: 0;
        font-family: 'Orbitron', sans-serif;
        font-size: 20px;
        font-weight: 800;
        letter-spacing: 2px;
        text-transform: uppercase;
      }
      #${OVERLAY_ID} .pn-verdict.safe .pn-verdict-text h3 { color: #00FF88; }
      #${OVERLAY_ID} .pn-verdict.caution .pn-verdict-text h3 { color: #FFC107; }
      #${OVERLAY_ID} .pn-verdict.suspicious .pn-verdict-text h3 { color: #F97316; }
      #${OVERLAY_ID} .pn-verdict.malicious .pn-verdict-text h3 { color: #FF4D4D; }
      #${OVERLAY_ID} .pn-verdict-text p {
        margin: 3px 0 0;
        font-size: 12px;
        color: #999;
      }

      /* Score bar */
      #${OVERLAY_ID} .pn-score-bar {
        height: 6px;
        background: rgba(255,255,255,0.06);
        border-radius: 3px;
        overflow: hidden;
      }
      #${OVERLAY_ID} .pn-score-fill {
        height: 100%;
        border-radius: 3px;
        transition: width 0.8s cubic-bezier(0.16, 1, 0.3, 1);
      }
      #${OVERLAY_ID} .pn-verdict.safe .pn-score-fill { background: linear-gradient(90deg, #00FF88, #10B981); }
      #${OVERLAY_ID} .pn-verdict.caution .pn-score-fill { background: linear-gradient(90deg, #FFC107, #F59E0B); }
      #${OVERLAY_ID} .pn-verdict.suspicious .pn-score-fill { background: linear-gradient(90deg, #F97316, #FB923C); }
      #${OVERLAY_ID} .pn-verdict.malicious .pn-score-fill { background: linear-gradient(90deg, #FF4D4D, #EF4444); }

      /* Score meta row */
      #${OVERLAY_ID} .pn-score-meta {
        display: flex;
        justify-content: space-between;
        margin-top: 8px;
        font-size: 11px;
        color: #666;
        font-family: 'Roboto Mono', monospace;
      }

      /* ─── Sections ─── */
      #${OVERLAY_ID} .pn-section {
        margin: 12px 16px 0;
        background: rgba(255,255,255,0.02);
        border-radius: 12px;
        border: 1px solid rgba(255,255,255,0.04);
        overflow: hidden;
      }
      #${OVERLAY_ID} .pn-section-head {
        display: flex;
        align-items: center;
        gap: 10px;
        padding: 12px 16px;
        border-bottom: 1px solid rgba(255,255,255,0.04);
        cursor: default;
      }
      #${OVERLAY_ID} .pn-section-icon {
        width: 28px; height: 28px;
        border-radius: 8px;
        display: flex;
        align-items: center;
        justify-content: center;
        flex-shrink: 0;
        background: rgba(11,99,217,0.1);
        border: 1px solid rgba(11,99,217,0.15);
      }
      #${OVERLAY_ID} .pn-section-icon svg { width: 14px; height: 14px; color: #0B63D9; }
      #${OVERLAY_ID} .pn-section-head h4 {
        margin: 0;
        font-size: 12px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.6px;
        color: #ccc;
      }
      #${OVERLAY_ID} .pn-section-body {
        padding: 12px 16px 14px;
      }

      /* Meta rows */
      #${OVERLAY_ID} .pn-meta {
        display: flex;
        align-items: baseline;
        padding: 5px 0;
        font-size: 13px;
        border-bottom: 1px solid rgba(255,255,255,0.03);
      }
      #${OVERLAY_ID} .pn-meta:last-child { border-bottom: none; }
      #${OVERLAY_ID} .pn-meta-k {
        color: #666;
        min-width: 105px;
        flex-shrink: 0;
        font-size: 12px;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.3px;
      }
      #${OVERLAY_ID} .pn-meta-v {
        color: #e0e0e0;
        word-break: break-all;
        font-family: 'Roboto Mono', monospace;
        font-size: 12.5px;
      }

      /* Auth chips */
      #${OVERLAY_ID} .pn-auth-chips {
        display: flex;
        flex-wrap: wrap;
        gap: 6px;
        margin-bottom: 6px;
      }
      #${OVERLAY_ID} .pn-chip {
        display: inline-flex;
        align-items: center;
        gap: 5px;
        padding: 5px 12px;
        border-radius: 6px;
        font-size: 12px;
        font-weight: 700;
        letter-spacing: 0.5px;
        font-family: 'Roboto Mono', monospace;
        border: 1px solid;
      }
      #${OVERLAY_ID} .pn-chip.pass {
        background: rgba(0,255,136,0.06);
        color: #00FF88;
        border-color: rgba(0,255,136,0.15);
      }
      #${OVERLAY_ID} .pn-chip.fail {
        background: rgba(255,77,77,0.06);
        color: #FF4D4D;
        border-color: rgba(255,77,77,0.15);
      }
      #${OVERLAY_ID} .pn-chip.na {
        background: rgba(255,255,255,0.03);
        color: #666;
        border-color: rgba(255,255,255,0.06);
      }
      #${OVERLAY_ID} .pn-chip-dot {
        width: 6px; height: 6px;
        border-radius: 50%;
        flex-shrink: 0;
      }
      #${OVERLAY_ID} .pn-chip.pass .pn-chip-dot { background: #00FF88; box-shadow: 0 0 6px rgba(0,255,136,0.5); }
      #${OVERLAY_ID} .pn-chip.fail .pn-chip-dot { background: #FF4D4D; box-shadow: 0 0 6px rgba(255,77,77,0.5); }
      #${OVERLAY_ID} .pn-chip.na .pn-chip-dot { background: #444; }

      /* DNS status rows */
      #${OVERLAY_ID} .pn-dns-row {
        display: flex;
        align-items: center;
        gap: 10px;
        padding: 7px 0;
        font-size: 13px;
        border-bottom: 1px solid rgba(255,255,255,0.03);
      }
      #${OVERLAY_ID} .pn-dns-row:last-child { border-bottom: none; }
      #${OVERLAY_ID} .pn-dns-dot {
        width: 8px; height: 8px;
        border-radius: 50%;
        flex-shrink: 0;
      }
      #${OVERLAY_ID} .pn-dns-dot.ok { background: #00FF88; box-shadow: 0 0 8px rgba(0,255,136,0.4); }
      #${OVERLAY_ID} .pn-dns-dot.bad { background: #FF4D4D; box-shadow: 0 0 8px rgba(255,77,77,0.4); }
      #${OVERLAY_ID} .pn-dns-label { color: #999; min-width: 80px; font-size: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.3px; }
      #${OVERLAY_ID} .pn-dns-val { color: #e0e0e0; font-family: 'Roboto Mono', monospace; font-size: 12.5px; }

      /* ─── Finding Items (indicator-style) ─── */
      #${OVERLAY_ID} .pn-finding {
        display: flex;
        align-items: center;
        gap: 10px;
        padding: 9px 12px;
        border-radius: 8px;
        margin-bottom: 6px;
        font-size: 12.5px;
        line-height: 1.5;
        color: #e0e0e0;
        border-left: 3px solid;
        background: rgba(255,255,255,0.02);
      }
      #${OVERLAY_ID} .pn-finding:last-child { margin-bottom: 0; }
      #${OVERLAY_ID} .pn-finding.safe { border-left-color: #00FF88; background: rgba(0,255,136,0.03); }
      #${OVERLAY_ID} .pn-finding.info { border-left-color: #0B63D9; background: rgba(11,99,217,0.04); }
      #${OVERLAY_ID} .pn-finding.low { border-left-color: #FFC107; background: rgba(255,193,7,0.03); }
      #${OVERLAY_ID} .pn-finding.medium { border-left-color: #F97316; background: rgba(249,115,22,0.04); }
      #${OVERLAY_ID} .pn-finding.high { border-left-color: #FF4D4D; background: rgba(255,77,77,0.04); }
      #${OVERLAY_ID} .pn-finding.critical { border-left-color: #DC2626; background: rgba(220,38,38,0.06); }
      #${OVERLAY_ID} .pn-finding-dot {
        width: 7px; height: 7px;
        border-radius: 50%;
        flex-shrink: 0;
      }
      #${OVERLAY_ID} .pn-finding.safe .pn-finding-dot { background: #00FF88; box-shadow: 0 0 6px rgba(0,255,136,0.4); }
      #${OVERLAY_ID} .pn-finding.info .pn-finding-dot { background: #0B63D9; box-shadow: 0 0 6px rgba(11,99,217,0.4); }
      #${OVERLAY_ID} .pn-finding.low .pn-finding-dot { background: #FFC107; box-shadow: 0 0 6px rgba(255,193,7,0.4); }
      #${OVERLAY_ID} .pn-finding.medium .pn-finding-dot { background: #F97316; box-shadow: 0 0 6px rgba(249,115,22,0.4); }
      #${OVERLAY_ID} .pn-finding.high .pn-finding-dot { background: #FF4D4D; box-shadow: 0 0 6px rgba(255,77,77,0.4); }
      #${OVERLAY_ID} .pn-finding.critical .pn-finding-dot { background: #DC2626; box-shadow: 0 0 6px rgba(220,38,38,0.5); }

      /* ─── Score Breakdown Grid ─── */
      #${OVERLAY_ID} .pn-scores-grid {
        display: grid;
        grid-template-columns: 1fr 1fr 1fr;
        gap: 8px;
      }
      #${OVERLAY_ID} .pn-score-card {
        background: rgba(255,255,255,0.03);
        border: 1px solid rgba(255,255,255,0.05);
        border-radius: 10px;
        padding: 12px;
        text-align: center;
      }
      #${OVERLAY_ID} .pn-score-card-val {
        font-family: 'Orbitron', sans-serif;
        font-size: 22px;
        font-weight: 800;
        color: #0B63D9;
        line-height: 1;
      }
      #${OVERLAY_ID} .pn-score-card-label {
        font-size: 10px;
        color: #666;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        margin-top: 5px;
        font-weight: 600;
      }

      /* ─── Scanning State ─── */
      #${OVERLAY_ID} .pn-scanning {
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        padding: 80px 20px 40px;
        text-align: center;
      }
      #${OVERLAY_ID} .pn-scan-ring {
        width: 56px; height: 56px;
        border: 3px solid rgba(255,255,255,0.06);
        border-top-color: #0B63D9;
        border-right-color: #00B7D9;
        border-radius: 50%;
        animation: pn-spin 0.9s linear infinite;
        margin-bottom: 20px;
        box-shadow: 0 0 20px rgba(11,99,217,0.2);
      }
      @keyframes pn-spin { to { transform: rotate(360deg); } }
      #${OVERLAY_ID} .pn-scan-text {
        font-family: 'Orbitron', sans-serif;
        font-size: 13px;
        font-weight: 600;
        color: #fff;
        letter-spacing: 1px;
        text-transform: uppercase;
        margin-bottom: 6px;
      }
      #${OVERLAY_ID} .pn-scan-phase {
        font-size: 12px;
        color: #666;
        font-family: 'Roboto Mono', monospace;
      }

      /* ─── Error State ─── */
      #${OVERLAY_ID} .pn-error {
        padding: 60px 20px;
        text-align: center;
      }
      #${OVERLAY_ID} .pn-error-icon {
        width: 48px; height: 48px;
        border-radius: 50%;
        background: rgba(255,77,77,0.1);
        border: 1px solid rgba(255,77,77,0.2);
        display: flex;
        align-items: center;
        justify-content: center;
        margin: 0 auto 16px;
      }
      #${OVERLAY_ID} .pn-error-icon svg { width: 24px; height: 24px; color: #FF4D4D; }
      #${OVERLAY_ID} .pn-error-title {
        font-family: 'Orbitron', sans-serif;
        font-size: 14px;
        font-weight: 700;
        color: #FF4D4D;
        margin-bottom: 6px;
        letter-spacing: 1px;
        text-transform: uppercase;
      }
      #${OVERLAY_ID} .pn-error-msg {
        font-size: 13px;
        color: #666;
      }

      /* Footer */
      #${OVERLAY_ID} .pn-footer {
        padding: 16px;
        text-align: center;
        font-size: 11px;
        color: #444;
        font-family: 'Roboto Mono', monospace;
        border-top: 1px solid rgba(255,255,255,0.04);
        margin-top: 12px;
      }
    `;
    document.head.appendChild(style);
  }

  // ════════════════════════════════════════════════════════════
  //  GMAIL HELPERS
  // ════════════════════════════════════════════════════════════

  const gmail = {
    /**
     * Detect if an email is currently open in Gmail.
     * Returns null if no email is open.
     */
    getEmailView() {
      // Gmail renders an email in an element with data-message-id or 
      // in a container with role="list" > role="listitem"
      // The most reliable selector: the email body container with class 'a3s'
      const emailBody = document.querySelector('.a3s.aiL');
      if (!emailBody) return null;

      // Find the parent conversation/message container
      // Gmail uses class 'nH' containers. Walk up to find the message root
      let messageRoot = emailBody.closest('[data-message-id]') || emailBody.closest('.gs');
      if (!messageRoot) {
        // Try legacy: the email view wrapper
        messageRoot = emailBody.closest('.h7') || emailBody.closest('.ii.gt');
      }

      return { emailBody, messageRoot };
    },

    /**
     * Get a unique key for the currently viewed email to avoid re-injection.
     */
    getEmailKey() {
      const msgEl = document.querySelector('[data-message-id]');
      if (msgEl) return msgEl.getAttribute('data-message-id');
      // Fallback: use URL hash
      const hash = location.hash;
      const match = hash.match(/#inbox\/([a-zA-Z0-9]+)/);
      return match ? match[1] : hash;
    },

    /**
     * Find the toolbar/action area where we inject the button.
     */
    getToolbar() {
      // Gmail's top action bar in email view has specific classes
      // Try the main toolbar above the email
      const toolbar = document.querySelector('.iH > div') ||
                      document.querySelector('.G-atb') ||
                      document.querySelector('[gh="tm"]') ||
                      document.querySelector('.bAo .ade');
      return toolbar;
    },

    /**
     * Extract email data from the currently viewed email.
     */
    extractEmailData() {
      const data = { headers: '', subject: '', body: '', sender: '', senderName: '', receiver: '', date: '' };

      // Subject
      const subjectEl = document.querySelector('h2.hP') || document.querySelector('[data-thread-perm-id]');
      data.subject = subjectEl ? subjectEl.textContent.trim() : '';

      // Sender (from visible UI)
      const senderEl = document.querySelector('.go') ||             // Sender name
                       document.querySelector('[email]') ||          // Email attribute
                       document.querySelector('.gD');                // Sender element
      if (senderEl) {
        data.sender = senderEl.getAttribute('email') || senderEl.textContent.trim();
        data.senderName = senderEl.getAttribute('name') || senderEl.textContent.trim();
      }

      // Receiver / To
      const toEl = document.querySelector('.g2') || document.querySelector('.cf.ix span[email]');
      if (toEl) {
        data.receiver = toEl.getAttribute('email') || toEl.textContent.trim();
      }

      // Date
      const dateEl = document.querySelector('.g3') || document.querySelector('[title][data-tooltip]');
      if (dateEl) {
        data.date = dateEl.getAttribute('title') || dateEl.textContent.trim();
      }

      // Body
      const bodyEl = document.querySelector('.a3s.aiL');
      data.body = bodyEl ? bodyEl.innerHTML : '';

      // Build pseudo-headers from UI data
      const headerLines = [];
      if (data.sender) headerLines.push(`From: ${data.senderName ? data.senderName + ' <' + data.sender + '>' : data.sender}`);
      if (data.receiver) headerLines.push(`To: ${data.receiver}`);
      if (data.subject) headerLines.push(`Subject: ${data.subject}`);
      if (data.date) headerLines.push(`Date: ${data.date}`);

      // Try to get the full headers from "Show original" data
      // Gmail exposes message details in hidden elements
      const allHeaders = document.querySelectorAll('.ajx .ajy');  // Header detail rows
      allHeaders.forEach(row => {
        const label = row.querySelector('td:first-child');
        const value = row.querySelector('td:last-child');
        if (label && value) {
          headerLines.push(`${label.textContent.trim()}: ${value.textContent.trim()}`);
        }
      });

      // Check for SPF/DKIM/DMARC in the "security details" dropdown
      const securityInfo = document.querySelector('.aZi') || document.querySelector('.aZj');
      if (securityInfo) {
        const secText = securityInfo.textContent;
        if (secText) headerLines.push(`X-Gmail-Security: ${secText.trim()}`);
      }

      data.headers = headerLines.join('\n');
      return data;
    },

    /**
     * Try to fetch full raw email via Gmail UI "Show Original" mechanism.
     * This is a best-effort attempt using the message ID.
     */
    async fetchRawHeaders() {
      try {
        const msgEl = document.querySelector('[data-message-id]');
        if (!msgEl) return null;
        const msgId = msgEl.getAttribute('data-message-id');
        const legacyId = msgEl.getAttribute('data-legacy-message-id');

        // Gmail exposes "Show original" which downloads the raw RFC 2822 message.
        // The URL pattern: /mail/u/0/?ui=2&ik=<ikvalue>&view=om&th=<thread_id>&
        // We can try to parse the ik value from the page
        const ikMatch = document.documentElement.innerHTML.match(/GLOBALS\[9\]="([^"]+)"/);
        const ik = ikMatch ? ikMatch[1] : null;

        if (!ik || !legacyId) return null;

        const url = `https://mail.google.com/mail/u/0/?ui=2&ik=${ik}&view=om&th=${legacyId}`;
        const resp = await fetch(url, { credentials: 'include' });
        if (!resp.ok) return null;

        const rawText = await resp.text();

        // Extract just the headers (everything before the first blank line)
        const headerEndIdx = rawText.indexOf('\r\n\r\n');
        const headerEndIdx2 = rawText.indexOf('\n\n');
        const endIdx = headerEndIdx !== -1 ? headerEndIdx : headerEndIdx2;

        if (endIdx !== -1) {
          return {
            headers: rawText.substring(0, endIdx),
            fullRaw: rawText
          };
        }
        return { headers: rawText, fullRaw: rawText };
      } catch (e) {
        console.log('[PhishNet Email] Could not fetch raw headers:', e.message);
        return null;
      }
    }
  };

  // ════════════════════════════════════════════════════════════
  //  OUTLOOK WEB HELPERS
  // ════════════════════════════════════════════════════════════

  const outlook = {
    getEmailView() {
      // Outlook Web renders email content in a div with role="document" or
      // inside .ReadingPaneContainerClass / [data-app-section="ReadingPane"]
      const readingPane = document.querySelector('[data-app-section="ReadingPane"]') ||
                          document.querySelector('[role="main"] [role="document"]') ||
                          document.querySelector('.ReadingPaneContainer') ||
                          document.querySelector('[aria-label*="Message body"]');
      if (!readingPane) return null;
      return { emailBody: readingPane, messageRoot: readingPane };
    },

    getEmailKey() {
      // Outlook uses ConversationId or ItemId in the URL
      const params = new URLSearchParams(location.search);
      const id = params.get('ItemID') || params.get('id');
      if (id) return id;
      // Fallback — look for data attributes
      const readingPane = document.querySelector('[data-app-section="ReadingPane"]');
      if (readingPane) {
        const uniqueEl = readingPane.querySelector('[data-convid]') || readingPane.querySelector('[data-uniqueid]');
        if (uniqueEl) return uniqueEl.getAttribute('data-convid') || uniqueEl.getAttribute('data-uniqueid');
      }
      return location.href;
    },

    getToolbar() {
      // Outlook's email action bar
      return document.querySelector('[data-app-section="ReadingPane"] [role="toolbar"]') ||
             document.querySelector('.ReadingPaneHeader [role="toolbar"]') ||
             document.querySelector('[aria-label="Message actions"] [role="toolbar"]');
    },

    extractEmailData() {
      const data = { headers: '', subject: '', body: '', sender: '', senderName: '', receiver: '', date: '' };

      // Subject
      const subjectEl = document.querySelector('[data-app-section="ReadingPane"] [role="heading"]') ||
                        document.querySelector('.SubjectLine') ||
                        document.querySelector('[aria-label*="Subject"]');
      data.subject = subjectEl ? subjectEl.textContent.trim() : '';

      // Sender
      const senderEl = document.querySelector('[data-app-section="ReadingPane"] .lpc_name_line') ||
                       document.querySelector('[data-app-section="ReadingPane"] [aria-label*="From"]') ||
                       document.querySelector('.SenderPersona') ||
                       document.querySelector('.sender-line .allowTextSelection');
      if (senderEl) {
        data.senderName = senderEl.textContent.trim();
        // Try to find the email address
        const emailEl = senderEl.closest('[email]') ||
                        document.querySelector('[data-app-section="ReadingPane"] .lpc_email') ||
                        senderEl.querySelector('[email]');
        data.sender = emailEl ? (emailEl.getAttribute('email') || emailEl.textContent.trim()) : data.senderName;
      }

      // To
      const toEl = document.querySelector('[data-app-section="ReadingPane"] [aria-label*="To"]') ||
                   document.querySelector('.ToRecipients');
      if (toEl) {
        data.receiver = toEl.textContent.trim();
      }

      // Date
      const dateEl = document.querySelector('[data-app-section="ReadingPane"] time') ||
                     document.querySelector('.DateLine') ||
                     document.querySelector('[aria-label*="Received"]');
      if (dateEl) {
        data.date = dateEl.getAttribute('datetime') || dateEl.textContent.trim();
      }

      // Body
      const bodyEl = document.querySelector('[aria-label*="Message body"]') ||
                     document.querySelector('[data-app-section="ReadingPane"] [role="document"]') ||
                     document.querySelector('.ReadingPaneContent [role="document"]');
      data.body = bodyEl ? bodyEl.innerHTML : '';

      // Build pseudo-headers
      const headerLines = [];
      if (data.sender) headerLines.push(`From: ${data.senderName ? data.senderName + ' <' + data.sender + '>' : data.sender}`);
      if (data.receiver) headerLines.push(`To: ${data.receiver}`);
      if (data.subject) headerLines.push(`Subject: ${data.subject}`);
      if (data.date) headerLines.push(`Date: ${data.date}`);

      // Outlook Web shows authentication results in the message detail area
      const detailPane = document.querySelector('[data-app-section="ReadingPane"] .messageDetailsWrapper') ||
                         document.querySelector('.messageHeader .full-header-view');
      if (detailPane) {
        const allText = detailPane.textContent;
        headerLines.push(`X-Outlook-Details: ${allText.trim()}`);
      }

      data.headers = headerLines.join('\n');
      return data;
    },

    async fetchRawHeaders() {
      // Outlook Web doesn't easily expose raw headers from the DOM
      // However, we can check for "View message source" / "View message details"
      return null;
    }
  };

  // Pick the right platform helpers
  const platform = PLATFORM === 'gmail' ? gmail : outlook;

  // ════════════════════════════════════════════════════════════
  //  BUTTON INJECTION
  // ════════════════════════════════════════════════════════════

  function createScanButton() {
    const btn = document.createElement('button');
    btn.id = BUTTON_ID;
    btn.innerHTML = `
      <svg class="phishnet-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      </svg>
      <span class="phishnet-label">Scan with PhishNet</span>
    `;
    btn.addEventListener('click', onScanClick);
    return btn;
  }

  function tryInjectButton() {
    // Bail if already injected for same email
    const currentKey = platform.getEmailKey();
    if (!currentKey) {
      removeButton();
      lastInjectedKey = null;
      return;
    }

    const emailView = platform.getEmailView();
    if (!emailView) {
      removeButton();
      lastInjectedKey = null;
      return;
    }

    if (currentKey === lastInjectedKey && document.getElementById(BUTTON_ID)) return;

    // Remove stale button
    removeButton();
    lastInjectedKey = currentKey;

    const btn = createScanButton();

    // Try to inject into the toolbar first
    const toolbar = platform.getToolbar();
    if (toolbar) {
      toolbar.appendChild(btn);
    } else {
      // Fallback: inject near the email body
      if (emailView.messageRoot) {
        emailView.messageRoot.insertBefore(btn, emailView.messageRoot.firstChild);
      } else {
        emailView.emailBody.parentElement?.insertBefore(btn, emailView.emailBody);
      }
    }

    console.log(`[PhishNet Email] Button injected for email: ${currentKey}`);
  }

  function removeButton() {
    const old = document.getElementById(BUTTON_ID);
    if (old) old.remove();
  }

  // ════════════════════════════════════════════════════════════
  //  SCAN FLOW
  // ════════════════════════════════════════════════════════════

  async function onScanClick(e) {
    e.preventDefault();
    e.stopPropagation();

    const btn = document.getElementById(BUTTON_ID);
    if (btn) {
      btn.classList.add('scanning');
      btn.innerHTML = `
        <svg class="phishnet-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="animation: phishnet-spin 2s linear infinite">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        </svg>
        <span class="phishnet-label">Scanning...</span>
      `;
    }

    // Show overlay with scanning state
    showOverlay({ scanning: true, phase: 'Extracting email data...' });

    try {
      // 1. Extract email data from DOM
      const emailData = platform.extractEmailData();
      console.log('[PhishNet Email] Extracted:', { subject: emailData.subject, sender: emailData.sender });

      updateOverlayPhase('Fetching raw email headers...');

      // 2. Try to get full raw headers (Gmail only — best effort)
      const rawData = await platform.fetchRawHeaders();
      if (rawData) {
        emailData.headers = rawData.headers;
        emailData.rawEmail = rawData.fullRaw;
        console.log('[PhishNet Email] Raw headers obtained (' + rawData.headers.length + ' bytes)');
      }

      updateOverlayPhase('Analyzing headers (IP, DNS, SPF, DKIM, DMARC)...');

      // 3. Send to background.js for backend scan
      const result = await sendToBackground(emailData);

      // 4. Display results
      showOverlay({ scanning: false, result });

    } catch (err) {
      console.error('[PhishNet Email] Scan error:', err);
      showOverlay({ scanning: false, error: err.message || 'Scan failed' });
    } finally {
      // Reset button
      if (btn) {
        btn.classList.remove('scanning');
        btn.innerHTML = `
          <svg class="phishnet-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          </svg>
          <span class="phishnet-label">Scan with PhishNet</span>
        `;
      }
    }
  }

  function sendToBackground(emailData) {
    return new Promise((resolve, reject) => {
      chrome.runtime.sendMessage({
        type: 'phishnet.email-scan',
        payload: {
          headers: emailData.headers,
          subject: emailData.subject,
          body: emailData.body,
          sender: emailData.sender,
          senderName: emailData.senderName,
          receiver: emailData.receiver,
          date: emailData.date,
          rawEmail: emailData.rawEmail || null,
          platform: PLATFORM
        }
      }, (response) => {
        if (chrome.runtime.lastError) {
          return reject(new Error(chrome.runtime.lastError.message));
        }
        if (response?.success) {
          resolve(response.data);
        } else {
          reject(new Error(response?.error || 'Unknown error'));
        }
      });
    });
  }

  // ════════════════════════════════════════════════════════════
  //  RESULTS OVERLAY
  // ════════════════════════════════════════════════════════════

  // SVG icon library (no emojis)
  const SVG = {
    shield: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
    shieldCheck: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>',
    shieldAlert: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>',
    shieldX: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="9" y1="9" x2="15" y2="15"/><line x1="15" y1="9" x2="9" y2="15"/></svg>',
    user: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>',
    lock: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>',
    globe: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>',
    route: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="6" cy="19" r="3"/><circle cx="18" cy="5" r="3"/><path d="M12 19h4.5a3.5 3.5 0 0 0 0-7h-8a3.5 3.5 0 0 1 0-7H12"/></svg>',
    info: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>',
    search: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>',
    fileText: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>',
    barChart: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg>',
    alertTriangle: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
    x: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>',
  };

  function showOverlay({ scanning, phase, result, error }) {
    let overlay = document.getElementById(OVERLAY_ID);
    if (!overlay) {
      overlay = document.createElement('div');
      overlay.id = OVERLAY_ID;
      document.body.appendChild(overlay);
    }

    if (scanning) {
      overlay.innerHTML = `
        <div class="pn-header">
          <div class="pn-header-brand">
            <div class="pn-header-logo">${SVG.shield}</div>
            <h2 class="pn-title">PhishNet</h2>
          </div>
          <button class="pn-close" id="phishnet-close-overlay">${SVG.x}</button>
        </div>
        <div class="pn-scanning">
          <div class="pn-scan-ring"></div>
          <div class="pn-scan-text">Analyzing Email</div>
          <div class="pn-scan-phase" id="phishnet-scan-phase">${phase || 'Initializing...'}</div>
        </div>
      `;
    } else if (error) {
      overlay.innerHTML = `
        <div class="pn-header">
          <div class="pn-header-brand">
            <div class="pn-header-logo">${SVG.shield}</div>
            <h2 class="pn-title">PhishNet</h2>
          </div>
          <button class="pn-close" id="phishnet-close-overlay">${SVG.x}</button>
        </div>
        <div class="pn-error">
          <div class="pn-error-icon">${SVG.alertTriangle}</div>
          <div class="pn-error-title">Scan Failed</div>
          <div class="pn-error-msg">${escapeHtml(error)}</div>
        </div>
      `;
    } else if (result) {
      overlay.innerHTML = buildResultHTML(result);
    }

    requestAnimationFrame(() => overlay.classList.add('visible'));

    setTimeout(() => {
      const closeBtn = document.getElementById('phishnet-close-overlay');
      if (closeBtn) {
        closeBtn.addEventListener('click', () => {
          overlay.classList.remove('visible');
          setTimeout(() => overlay.remove(), 350);
        });
      }
    }, 50);
  }

  function updateOverlayPhase(phase) {
    const el = document.getElementById('phishnet-scan-phase');
    if (el) el.textContent = phase;
  }

  function buildResultHTML(r) {
    const vc = (r.verdict || 'safe').toLowerCase();
    const verdictSVG = { safe: SVG.shieldCheck, caution: SVG.shieldAlert, suspicious: SVG.shieldAlert, malicious: SVG.shieldX };
    const verdictDesc = {
      safe: 'This email appears legitimate and safe.',
      caution: 'Some minor signals detected — review with care.',
      suspicious: 'Multiple warning signs detected — proceed with caution.',
      malicious: 'High-risk email — likely phishing or malicious.'
    };
    const score = r.score ?? 0;

    let html = `
      <div class="pn-header">
        <div class="pn-header-brand">
          <div class="pn-header-logo">${SVG.shield}</div>
          <h2 class="pn-title">PhishNet</h2>
        </div>
        <button class="pn-close" id="phishnet-close-overlay">${SVG.x}</button>
      </div>

      <div class="pn-verdict ${vc}">
        <div class="pn-verdict-top">
          <div class="pn-verdict-icon">${verdictSVG[vc] || SVG.shield}</div>
          <div class="pn-verdict-text">
            <h3>${r.verdict || 'UNKNOWN'}</h3>
            <p>${verdictDesc[vc] || ''}</p>
          </div>
        </div>
        <div class="pn-score-bar">
          <div class="pn-score-fill" style="width: ${Math.max(score, 2)}%"></div>
        </div>
        <div class="pn-score-meta">
          <span>Risk Score: ${score}/100</span>
          <span>${r.meta?.scanTime || 0}ms</span>
        </div>
      </div>
    `;

    // ── Sender Info ──
    const sender = r.headerAnalysis?.sender;
    if (sender) {
      html += `
        <div class="pn-section">
          <div class="pn-section-head">
            <div class="pn-section-icon">${SVG.user}</div>
            <h4>Sender Information</h4>
          </div>
          <div class="pn-section-body">
            ${pnMeta('From', sender.fromName ? `${escapeHtml(sender.fromName)} &lt;${escapeHtml(sender.from)}&gt;` : escapeHtml(sender.from))}
            ${sender.replyTo ? pnMeta('Reply-To', escapeHtml(sender.replyTo)) : ''}
            ${sender.returnPath ? pnMeta('Return-Path', escapeHtml(sender.returnPath)) : ''}
            ${pnMeta('Domain', escapeHtml(sender.fromDomain || 'Unknown'))}
          </div>
        </div>
      `;
    }

    // ── Authentication ──
    const auth = r.headerAnalysis?.authentication;
    if (auth) {
      html += `
        <div class="pn-section">
          <div class="pn-section-head">
            <div class="pn-section-icon">${SVG.lock}</div>
            <h4>Authentication</h4>
          </div>
          <div class="pn-section-body">
            <div class="pn-auth-chips">
              ${pnChip('SPF', auth.spf?.result)}
              ${pnChip('DKIM', auth.dkim?.result)}
              ${pnChip('DMARC', auth.dmarc?.result)}
              ${auth.arc?.result ? pnChip('ARC', auth.arc.result) : ''}
            </div>
            ${auth.fullyAuthenticated ? pnFinding({ severity: 'safe', detail: 'Fully authenticated — SPF + DKIM + DMARC all passed' }) : ''}
          </div>
        </div>
      `;
    }

    // ── DNS Verification ──
    const dns = r.headerAnalysis?.dns;
    if (dns) {
      html += `
        <div class="pn-section">
          <div class="pn-section-head">
            <div class="pn-section-icon">${SVG.globe}</div>
            <h4>DNS Verification</h4>
          </div>
          <div class="pn-section-body">
            ${pnDns('SPF', dns.spf?.exists, dns.spf?.exists ? (dns.spf.strict ? 'Strict (-all)' : (dns.spf.softfail ? 'Soft-fail (~all)' : 'Published')) : 'Not found')}
            ${pnDns('DMARC', dns.dmarc?.exists, dns.dmarc?.exists ? (dns.dmarc.policy || 'none').toUpperCase() : 'Not found')}
            ${pnDns('MX', dns.mx?.exists, dns.mx?.exists ? `${dns.mx.records?.length || 0} record(s)` : 'Not found')}
          </div>
        </div>
      `;
    }

    // ── Routing ──
    const routing = r.headerAnalysis?.routing;
    if (routing && (routing.hops > 0 || routing.ips?.length > 0)) {
      html += `
        <div class="pn-section">
          <div class="pn-section-head">
            <div class="pn-section-icon">${SVG.route}</div>
            <h4>Email Routing</h4>
          </div>
          <div class="pn-section-body">
            ${pnMeta('Hops', routing.hops)}
            ${routing.ips?.length > 0 ? pnMeta('Source IPs', routing.ips.map(escapeHtml).join(', ')) : ''}
            ${(routing.ipDetails || []).filter(i => i.hostnames?.length > 0).map(i => pnMeta('IP ' + escapeHtml(i.ip), i.hostnames.map(escapeHtml).join(', '))).join('')}
          </div>
        </div>
      `;
    }

    // ── Metadata ──
    const meta = r.headerAnalysis?.metadata;
    if (meta) {
      html += `
        <div class="pn-section">
          <div class="pn-section-head">
            <div class="pn-section-icon">${SVG.info}</div>
            <h4>Metadata</h4>
          </div>
          <div class="pn-section-body">
            ${meta.date ? pnMeta('Date', escapeHtml(meta.date)) : ''}
            ${meta.messageId ? pnMeta('Message-ID', escapeHtml(meta.messageId)) : ''}
            ${meta.xMailer ? pnMeta('Mailer', escapeHtml(meta.xMailer)) : ''}
            ${pnMeta('Unsubscribe', meta.listUnsubscribe ? '<span style="color:#00FF88">Present</span>' : '<span style="color:#666">Not present</span>')}
          </div>
        </div>
      `;
    }

    // ── Header Findings ──
    const hf = r.headerAnalysis?.findings;
    if (hf && hf.length > 0) {
      html += `
        <div class="pn-section">
          <div class="pn-section-head">
            <div class="pn-section-icon">${SVG.search}</div>
            <h4>Header Analysis</h4>
          </div>
          <div class="pn-section-body">
            ${hf.map(f => pnFinding(f)).join('')}
          </div>
        </div>
      `;
    }

    // ── Body Findings ──
    const bf = r.bodyAnalysis?.findings;
    if (bf && bf.length > 0) {
      html += `
        <div class="pn-section">
          <div class="pn-section-head">
            <div class="pn-section-icon">${SVG.fileText}</div>
            <h4>Content Analysis</h4>
          </div>
          <div class="pn-section-body">
            ${bf.map(f => pnFinding(f)).join('')}
          </div>
        </div>
      `;
    }

    // ── Score Breakdown ──
    html += `
      <div class="pn-section">
        <div class="pn-section-head">
          <div class="pn-section-icon">${SVG.barChart}</div>
          <h4>Score Breakdown</h4>
        </div>
        <div class="pn-section-body">
          <div class="pn-scores-grid">
            <div class="pn-score-card">
              <div class="pn-score-card-val">${r.headerAnalysis?.score ?? 0}</div>
              <div class="pn-score-card-label">Header</div>
            </div>
            <div class="pn-score-card">
              <div class="pn-score-card-val">${r.bodyAnalysis?.score ?? 0}</div>
              <div class="pn-score-card-label">Content</div>
            </div>
            <div class="pn-score-card">
              <div class="pn-score-card-val">${score}</div>
              <div class="pn-score-card-label">Combined</div>
            </div>
          </div>
          ${r.headerAnalysis?.isVerifiedLegit ? pnFinding({ severity: 'safe', detail: 'Verified legitimate sender — content signals dampened' }) : ''}
        </div>
      </div>
    `;

    // Footer
    html += `<div class="pn-footer">PhishNet Email Scanner v1.0</div>`;

    return html;
  }

  // ── HTML Helpers ──
  function pnMeta(label, value) {
    return `<div class="pn-meta"><span class="pn-meta-k">${label}</span><span class="pn-meta-v">${value ?? '—'}</span></div>`;
  }

  function pnChip(name, result) {
    if (!result) return `<span class="pn-chip na"><span class="pn-chip-dot"></span>${name}: N/A</span>`;
    const cls = result === 'pass' ? 'pass' : (result === 'fail' || result === 'softfail' ? 'fail' : 'na');
    return `<span class="pn-chip ${cls}"><span class="pn-chip-dot"></span>${name}: ${result.toUpperCase()}</span>`;
  }

  function pnDns(label, ok, value) {
    return `<div class="pn-dns-row"><span class="pn-dns-dot ${ok ? 'ok' : 'bad'}"></span><span class="pn-dns-label">${label}</span><span class="pn-dns-val">${value}</span></div>`;
  }

  function pnFinding(f) {
    return `<div class="pn-finding ${f.severity || 'info'}"><span class="pn-finding-dot"></span><span>${escapeHtml(f.detail || '')}</span></div>`;
  }

  function escapeHtml(s) {
    const d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
  }

  // ════════════════════════════════════════════════════════════
  //  POLLING LOOP
  // ════════════════════════════════════════════════════════════

  function startWatcher() {
    injectStyles();

    // Initial attempt
    tryInjectButton();

    // Poll periodically (Gmail/Outlook are SPAs — DOM changes as user navigates)
    setInterval(() => {
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(tryInjectButton, DEBOUNCE_MS);
    }, CHECK_INTERVAL_MS);

    // Also watch for Gmail/Outlook SPA navigation via hashchange / popstate
    window.addEventListener('hashchange', () => {
      setTimeout(tryInjectButton, 300);
    });
    window.addEventListener('popstate', () => {
      setTimeout(tryInjectButton, 300);
    });

    // MutationObserver for deep DOM changes (email open/close)
    const observer = new MutationObserver(() => {
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(tryInjectButton, DEBOUNCE_MS);
    });

    observer.observe(document.body, {
      childList: true,
      subtree: true,
      attributes: false,
      characterData: false
    });
  }

  // ════════════════════════════════════════════════════════════
  //  INIT
  // ════════════════════════════════════════════════════════════

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', startWatcher);
  } else {
    startWatcher();
  }

})();
