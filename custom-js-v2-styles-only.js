/**
 * ============================================================================
 * Eden Bridge — Status Styles v1.0 for GHL Marketplace
 * ============================================================================
 * Version : 1.0.0 | Updated: 2026-02-18
 *
 * WHAT THIS DOES:
 *  1. Apple-style glow on outbound (right-side) message bubbles
 *     when iMessage tab is active
 *  2. iMessage tab gets a subtle blue glow indicator
 *  3. Status messages (Delivered, Read, SMS, RCS) styled as small
 *     gray line indicators with CSS icons — no emojis
 *  4. MutationObserver to re-apply styles as new messages load
 *
 * NOTE: Tab reordering and auto-select handled by "iMessage First" v1.0
 * ============================================================================
 */

(function () {
  "use strict";

  /* ========================================================================= */
  /* 1. CSS                                                                     */
  /* ========================================================================= */

  const CSS = `
    /* -- iMessage Tab Glow -- */
    .eden-imessage-tab {
      box-shadow:
        0 0 0 2px rgba(0, 122, 255, 0.20),
        0 2px 10px rgba(0, 122, 255, 0.12) !important;
      border-color: rgba(0, 122, 255, 0.35) !important;
      transition: box-shadow 0.2s ease !important;
    }

    /* -- Outbound Bubble Glow (only when iMessage active) -- */
    body.eden-imessage-active .conversation-message.outbound .message-bubble,
    body.eden-imessage-active .conversation-message.sent    .message-bubble,
    body.eden-imessage-active .message-wrapper.outbound     .message-content,
    body.eden-imessage-active [class*="message"][class*="outbound"] [class*="bubble"],
    body.eden-imessage-active [class*="message"][class*="sent"]     [class*="bubble"],
    body.eden-imessage-active .msg-bubble.outbound,
    body.eden-imessage-active .msg-bubble.sent,
    body.eden-imessage-active div[class*="message-item"][class*="from-me"] {
      box-shadow:
        0 0 0 1px rgba(0, 122, 255, 0.10),
        0 2px 14px rgba(0, 122, 255, 0.16),
        0 1px 4px  rgba(0, 0, 0, 0.06) !important;
      transition: box-shadow 0.2s ease !important;
    }

    body.eden-imessage-active .conversation-message.outbound .message-bubble:hover,
    body.eden-imessage-active [class*="message"][class*="outbound"] [class*="bubble"]:hover {
      box-shadow:
        0 0 0 1px rgba(0, 122, 255, 0.20),
        0 3px 20px rgba(0, 122, 255, 0.24),
        0 1px 4px  rgba(0, 0, 0, 0.08) !important;
    }

    /* -- Status indicator row (strip bubble chrome) -- */
    .eden-status-wrapper [class*="bubble"],
    .eden-status-wrapper [class*="message-content"],
    .eden-status-wrapper [class*="message-body"] {
      background:    transparent !important;
      box-shadow:    none !important;
      border:        none !important;
      padding:       0 !important;
      border-radius: 0 !important;
    }

    .eden-status-row {
      display:        flex !important;
      align-items:    center !important;
      justify-content: flex-end !important;
      gap:            4px !important;
      font-size:      11px !important;
      font-weight:    400 !important;
      line-height:    1.4 !important;
      letter-spacing: 0.01em !important;
      color:          #8e8e93 !important;
      margin:         -4px 8px 6px 0 !important;
      padding:        0 !important;
      background:     transparent !important;
      border:         none !important;
      box-shadow:     none !important;
      font-family:    -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif !important;
    }

    .eden-status-row::before {
      font-style:  normal !important;
      font-weight: 600 !important;
      font-size:   11px !important;
      line-height: 1 !important;
      flex-shrink: 0 !important;
    }

    /* Delivered via iMessage - single gray checkmark */
    .eden-status-delivered::before {
      content: "\\2713";
      color:   #8e8e93 !important;
    }

    /* Read - double blue checkmarks */
    .eden-status-read::before {
      content:        "\\2713\\2713";
      color:          #007aff !important;
      font-size:      10px !important;
      letter-spacing: -2px !important;
      margin-right:   3px !important;
    }

    /* Sent as SMS - orange warning */
    .eden-status-sms::before {
      content:   "\\25B2";
      color:     #ff9500 !important;
      font-size: 8px !important;
    }
    .eden-status-sms {
      color: #ff9500 !important;
    }

    /* Delivered via RCS - green indicator */
    .eden-status-rcs::before {
      content:   "\\2299";
      color:     #34c759 !important;
      font-size: 10px !important;
    }
    .eden-status-rcs {
      color: #34c759 !important;
    }
  `;

  function injectCSS() {
    if (document.getElementById("eden-bridge-styles")) return;
    const style = document.createElement("style");
    style.id = "eden-bridge-styles";
    style.textContent = CSS;
    document.head.appendChild(style);
  }

  /* ========================================================================= */
  /* 2. iMessage TAB DETECTION                                                  */
  /* ========================================================================= */

  function isIMessageTabActive() {
    for (const sel of [
      "[role='tab'][aria-selected='true']",
      "[class*='tab'][class*='active']",
      "button[class*='active']",
    ]) {
      const el = document.querySelector(sel);
      if (el && (el.textContent || "").toLowerCase().includes("imessage")) {
        el.classList.add("eden-imessage-tab");
        return true;
      }
    }
    return false;
  }

  function applyIMessageBodyClass() {
    if (isIMessageTabActive()) {
      document.body.classList.add("eden-imessage-active");
    } else {
      document.body.classList.remove("eden-imessage-active");
    }
  }

  /* ========================================================================= */
  /* 3. STATUS MESSAGE DETECTION & STYLING                                      */
  /* ========================================================================= */

  const STATUS_PATTERNS = [
    { test: /^Delivered via iMessage/i, cls: "eden-status-delivered" },
    { test: /^Read \d/i,                cls: "eden-status-read" },
    { test: /^Sent as SMS/i,            cls: "eden-status-sms" },
    { test: /^Delivered via RCS/i,      cls: "eden-status-rcs" },
  ];

  function detectStatusClass(text) {
    const t = (text || "").trim();
    for (const { test, cls } of STATUS_PATTERNS) {
      if (test.test(t)) return cls;
    }
    return null;
  }

  function applyStatusStyling(root) {
    const selectors = [
      "[class*='message-item']",
      "[class*='chat-message']",
      "[class*='conversation-message']",
      "[class*='message-wrapper']",
      "[class*='msg-row']",
    ];

    for (const sel of selectors) {
      for (const item of (root || document).querySelectorAll(sel)) {
        if (item.dataset.edenStyled) continue;

        const textEl =
          item.querySelector("[class*='message-body']") ||
          item.querySelector("[class*='message-text']") ||
          item.querySelector("[class*='bubble-text']") ||
          item.querySelector("[class*='content']") ||
          item;

        const rawText = (textEl.textContent || "").trim();
        const statusCls = detectStatusClass(rawText);

        if (statusCls) {
          item.dataset.edenStyled = "status";
          item.classList.add("eden-status-wrapper");
          item.style.setProperty("margin-top", "0", "important");
          item.style.setProperty("margin-bottom", "2px", "important");
          item.style.setProperty("min-height", "auto", "important");

          const span = document.createElement("span");
          span.className = "eden-status-row " + statusCls;
          span.textContent = rawText;

          textEl.innerHTML = "";
          textEl.appendChild(span);
        } else {
          item.dataset.edenStyled = "message";
        }
      }
    }
  }

  /* ========================================================================= */
  /* 4. MUTATION OBSERVER                                                       */
  /* ========================================================================= */

  let _debounce = null;

  function onDOMChange() {
    clearTimeout(_debounce);
    _debounce = setTimeout(function () {
      applyStatusStyling();
      applyIMessageBodyClass();
    }, 150);
  }

  /* ========================================================================= */
  /* 5. SPA NAVIGATION HOOK                                                     */
  /* ========================================================================= */

  var lastUrl = location.href;

  setInterval(function () {
    if (location.href !== lastUrl) {
      lastUrl = location.href;
      setTimeout(function () {
        applyStatusStyling();
        applyIMessageBodyClass();
      }, 500);
    }
  }, 500);

  document.addEventListener("click", function (e) {
    var row = e.target.closest(
      "[class*='conversation-item'], [class*='chat-item'], [class*='contact-item'], [data-conversation-id]"
    );
    if (row) {
      setTimeout(function () {
        applyStatusStyling();
        applyIMessageBodyClass();
      }, 600);
    }
  }, true);

  /* ========================================================================= */
  /* 6. INIT                                                                    */
  /* ========================================================================= */

  function init() {
    injectCSS();
    applyStatusStyling();
    applyIMessageBodyClass();

    var observer = new MutationObserver(onDOMChange);
    observer.observe(document.body, { childList: true, subtree: true });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }

  window.addEventListener("load", function () {
    setTimeout(function () {
      applyStatusStyling();
      applyIMessageBodyClass();
    }, 1000);
  });

})();
