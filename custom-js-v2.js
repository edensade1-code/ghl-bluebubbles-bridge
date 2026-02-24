/**
 * ============================================================================
 * Eden Bridge — Custom JS v2.0 for GHL Marketplace
 * ============================================================================
 * Version : 4.3.0 | Updated: 2026-02-24
 *
 * WHAT THIS DOES:
 *  1. Reorders conversation tabs so iMessage appears first
 *  2. Auto-selects the iMessage tab when opening a conversation
 *  3. Injects CSS:
 *     - Apple-style glow on outbound (right-side) message bubbles
 *     - iMessage tab gets a subtle blue glow indicator
 *     - Status messages styled as small gray line indicators with
 *       CSS pseudo-element icons (single/double checkmarks, alert)
 *       — NO emojis, professional like WhatsApp delivery ticks
 *  4. MutationObserver to re-apply styles as new messages load
 *
 * HOW TO INSTALL:
 *  GHL → Settings → Marketplace → Your App → Custom JS/CSS
 *  Paste the entire contents of this file.
 * ============================================================================
 */

(function () {
  "use strict";

  /* ========================================================================= */
  /* 1. CSS                                                                     */
  /* ========================================================================= */

  const CSS = `
    /* ── iMessage Tab Glow ───────────────────────────────────────────────── */

    /*
     * Broad selectors — GHL's class names vary by version so we cast a wide net.
     * The .eden-imessage-tab class is added by JS when we find the active tab.
     */
    .eden-imessage-tab {
      box-shadow:
        0 0 0 2px rgba(0, 122, 255, 0.20),
        0 2px 10px rgba(0, 122, 255, 0.12) !important;
      border-color: rgba(0, 122, 255, 0.35) !important;
      transition: box-shadow 0.2s ease !important;
    }

    /* ── Outbound Bubble Glow ─────────────────────────────────────────────── */
    /*
     * Applied when body has .eden-imessage-active.
     * Targets right-side / outbound / sent message bubbles.
     */
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

    /* ── Status indicator row ────────────────────────────────────────────── */
    /*
     * Eden Bridge pushes status messages as plain text into the GHL thread:
     *   "Delivered via iMessage · 3:45 PM"
     *   "Read 3:45 PM"
     *   "Sent as SMS (contact may not have iMessage)"
     *   "Delivered via RCS · 3:45 PM"
     *
     * We detect these by text content and apply .eden-status-* classes.
     * The wrapper loses its bubble chrome; the inner span gets a small icon
     * via ::before using standard unicode (not emoji).
     */

    /* Strip bubble chrome from the wrapper */
    .eden-status-wrapper [class*="bubble"],
    .eden-status-wrapper [class*="message-content"],
    .eden-status-wrapper [class*="message-body"] {
      background:    transparent !important;
      box-shadow:    none !important;
      border:        none !important;
      padding:       0 !important;
      border-radius: 0 !important;
    }

    /* The indicator text row itself */
    .eden-status-row {
      display:        flex !important;
      align-items:    center !important;
      justify-content: flex-end !important;   /* right-align like delivery ticks */
      gap:            4px !important;
      font-size:      11px !important;
      font-weight:    400 !important;
      line-height:    1.4 !important;
      letter-spacing: 0.01em !important;
      color:          #8e8e93 !important;      /* Apple system-gray */
      margin:         -4px 8px 6px 0 !important;
      padding:        0 !important;
      background:     transparent !important;
      border:         none !important;
      box-shadow:     none !important;
      font-family:    -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif !important;
    }

    /* Icon ::before — base */
    .eden-status-row::before {
      font-style:  normal !important;
      font-weight: 600 !important;
      font-size:   11px !important;
      line-height: 1 !important;
      flex-shrink: 0 !important;
    }

    /*
     * Delivered via iMessage → single checkmark (like WhatsApp grey tick)
     * Unicode: ✓  U+2713  — renders as a plain text glyph, NOT an emoji
     */
    .eden-status-delivered::before {
      content: "✓";
      color:   #8e8e93 !important;  /* gray */
    }

    /*
     * Read → double checkmark, blue (like WhatsApp blue double-tick)
     * We use two stacked ✓ via a custom multi-char approach.
     */
    .eden-status-read::before {
      content:      "✓✓";
      color:        #007aff !important;   /* Apple blue */
      font-size:    10px !important;
      letter-spacing: -2px !important;   /* tighten the two ticks together */
      margin-right: 3px !important;
    }

    /*
     * Sent as SMS → small triangle-exclamation warning
     * Unicode: ▲  U+25B2  — plain geometric shape, no emoji
     */
    .eden-status-sms::before {
      content:   "▲";
      color:     #ff9500 !important;   /* Apple orange */
      font-size: 8px !important;
    }
    .eden-status-sms {
      color: #ff9500 !important;   /* orange for the text too */
    }

    /*
     * Delivered via RCS → small info circle
     * Unicode: ⊙  U+2299  — plain math symbol, no emoji
     */
    .eden-status-rcs::before {
      content: "⊙";
      color:   #34c759 !important;   /* Apple green */
      font-size: 10px !important;
    }
    .eden-status-rcs {
      color: #34c759 !important;
    }
  `;

  function injectCSS() {
    if (document.getElementById("eden-bridge-v2-styles")) return;
    const style = document.createElement("style");
    style.id    = "eden-bridge-v2-styles";
    style.textContent = CSS;
    document.head.appendChild(style);
    console.log("[EdenBridge] CSS injected");
  }

  /* ========================================================================= */
  /* 2. TAB REORDERING — Move iMessage tab to the front                       */
  /* ========================================================================= */

  function reorderTabs() {
    const containerSelectors = [
      ".conversation-channel-tabs",
      ".channel-selector-tabs",
      ".provider-tabs-container",
      "[class*='channel-tab-list']",
      "[class*='message-tab-container']",
    ];

    for (const sel of containerSelectors) {
      const container = document.querySelector(sel);
      if (!container) continue;

      const tabs = Array.from(container.children);
      const iMsg = tabs.find((t) =>
        (t.textContent || "").toLowerCase().includes("imessage") ||
        (t.getAttribute("data-tab")   || "").toLowerCase() === "imessage" ||
        (t.getAttribute("data-value") || "").toLowerCase() === "imessage"
      );

      if (iMsg && container.firstChild !== iMsg) {
        container.insertBefore(iMsg, container.firstChild);
        console.log("[EdenBridge] iMessage tab moved to front");
      }
    }
  }

  /* ========================================================================= */
  /* 3. AUTO-SELECT iMessage TAB                                               */
  /* ========================================================================= */

  let lastAutoSelected = null;

  function autoSelectIMessageTab() {
    const candidateSelectors = [
      "button[data-tab='iMessage']",
      "button[data-value='iMessage']",
      "button[aria-label*='iMessage']",
      "[class*='tab-button']:not([disabled])",
      "[class*='channel-tab']:not([disabled])",
      "[role='tab']:not([disabled])",
    ];

    for (const sel of candidateSelectors) {
      for (const btn of document.querySelectorAll(sel)) {
        const text = (btn.textContent || btn.getAttribute("aria-label") || "").trim();
        if (!text.toLowerCase().includes("imessage")) continue;

        const isActive =
          btn.classList.contains("active") ||
          btn.getAttribute("aria-selected") === "true" ||
          btn.getAttribute("data-selected") === "true";
        if (isActive) {
          btn.classList.add("eden-imessage-tab");
          return;
        }

        const key = btn.outerHTML.slice(0, 80);
        if (key === lastAutoSelected && Date.now() - (window._edenLastTabClick || 0) < 2000) return;

        btn.click();
        btn.classList.add("eden-imessage-tab");
        lastAutoSelected           = key;
        window._edenLastTabClick  = Date.now();
        console.log("[EdenBridge] Auto-selected iMessage tab");
        return;
      }
    }
  }

  /* ========================================================================= */
  /* 4. STATUS MESSAGE DETECTION                                               */
  /* ========================================================================= */

  /*
   * Match the plain-text status strings that Eden Bridge pushes into GHL.
   * No emoji — purely text patterns.
   */
  const STATUS_PATTERNS = [
    // "Delivered via iMessage · 3:45 PM"
    { test: /^Delivered via iMessage/i,  cls: "eden-status-delivered" },
    // "Read 3:45 PM"
    { test: /^Read \d/i,                  cls: "eden-status-read"      },
    // "Sent as SMS ..."  OR  "Sent as SMS · Delivered ..."
    { test: /^Sent as SMS/i,              cls: "eden-status-sms"       },
    // "Delivered via RCS · 3:45 PM"
    { test: /^Delivered via RCS/i,        cls: "eden-status-rcs"       },
  ];

  function detectStatusClass(text) {
    const t = (text || "").trim();
    for (const { test, cls } of STATUS_PATTERNS) {
      if (test.test(t)) return cls;
    }
    return null;
  }

  /* ========================================================================= */
  /* 5. APPLY STATUS STYLING TO MESSAGE ITEMS                                  */
  /* ========================================================================= */

  /*
   * Strategy: walk ALL elements in the message area, check innerText of
   * leaf-ish elements. When a status match is found, walk UP the DOM to
   * find the outermost "message row" container and restyle the whole thing.
   *
   * This is intentionally aggressive — GHL class names change often,
   * so we rely on TEXT CONTENT, not selectors.
   */

  function findMessageRow(el) {
    // Walk up from the text element to find the message row container.
    // Heuristic: it's the ancestor that represents one "row" in the chat.
    // Usually has a significant height, margin, or is a direct child of the
    // scrollable message list.
    let node = el;
    let candidate = el;
    let depth = 0;
    while (node && node !== document.body && depth < 15) {
      // If parent is the scrollable container (large list of messages), stop here
      const parent = node.parentElement;
      if (!parent) break;
      
      const siblings = parent.children.length;
      // Message lists typically have many siblings (each message is one)
      if (siblings > 3) {
        candidate = node;
      }
      node = parent;
      depth++;
    }
    return candidate;
  }

  function applyStatusStyling(root = document) {
    // Find the message container area — usually a scrollable div with many children
    const containers = root.querySelectorAll(
      "[class*='message-list'], [class*='chat-body'], [class*='conversation-body'], " +
      "[class*='messages-container'], [class*='msg-list'], [class*='message-area'], " +
      "[class*='chat-messages'], [class*='conversation-messages']"
    );

    // Also try: any scrollable div with 5+ children that contains message-like content
    const allDivs = containers.length > 0 ? containers : root.querySelectorAll("div[style*='overflow']");

    // Broad scan: find all elements whose trimmed text matches a status pattern
    // and whose text is SHORT (status messages are always <60 chars)
    const walker = document.createTreeWalker(
      root.body || root,
      NodeFilter.SHOW_ELEMENT,
      {
        acceptNode(node) {
          if (node.dataset && node.dataset.edenStyled) return NodeFilter.FILTER_REJECT;
          // Only check elements that DIRECTLY contain text (leaf-ish)
          const text = node.textContent?.trim() || "";
          if (text.length > 0 && text.length < 80 && node.children.length < 5) {
            return NodeFilter.FILTER_ACCEPT;
          }
          return NodeFilter.FILTER_SKIP;
        }
      }
    );

    const hits = [];
    let walkNode;
    while ((walkNode = walker.nextNode())) {
      const text = walkNode.textContent.trim();
      const cls = detectStatusClass(text);
      if (cls) hits.push({ el: walkNode, text, cls });
    }

    for (const { el, text, cls } of hits) {
      // Find the message row (outermost container for this single message)
      const row = findMessageRow(el);
      if (row.dataset.edenStyled) continue;

      row.dataset.edenStyled = "status";
      row.classList.add("eden-status-wrapper");
      row.style.setProperty("margin-top",    "0",     "important");
      row.style.setProperty("margin-bottom", "2px",   "important");
      row.style.setProperty("min-height",    "auto",  "important");
      row.style.setProperty("padding",       "0 8px", "important");

      // Collapse ALL descendant containers to strip bubble chrome
      for (const child of row.querySelectorAll("*")) {
        const s = getComputedStyle(child);
        if (s.backgroundColor && s.backgroundColor !== "rgba(0, 0, 0, 0)" && s.backgroundColor !== "transparent") {
          child.style.setProperty("background", "transparent", "important");
        }
        if (s.boxShadow && s.boxShadow !== "none") {
          child.style.setProperty("box-shadow", "none", "important");
        }
        if (s.border && s.border !== "none" && !s.border.includes("0px")) {
          child.style.setProperty("border", "none", "important");
        }
        if (parseInt(s.padding) > 4) {
          child.style.setProperty("padding", "0", "important");
        }
        if (parseInt(s.borderRadius) > 0) {
          child.style.setProperty("border-radius", "0", "important");
        }
      }

      // Build the indicator span
      const span      = document.createElement("span");
      span.className  = `eden-status-row ${cls}`;
      span.textContent = text;

      // Find the innermost text-bearing element and replace content
      const textEl = el.children.length === 0 ? el : 
        el.querySelector("[class*='body']") || 
        el.querySelector("[class*='text']") || 
        el.querySelector("[class*='content']") || 
        el.querySelector("p, span") || el;
      
      textEl.innerHTML = "";
      textEl.appendChild(span);
    }

    // Also mark non-status messages so we don't re-scan them
    const msgSelectors = [
      "[class*='message-item']", "[class*='chat-message']", "[class*='conversation-message']",
      "[class*='message-wrapper']", "[class*='msg-row']",
    ];
    for (const sel of msgSelectors) {
      for (const item of root.querySelectorAll(sel)) {
        if (!item.dataset.edenStyled) {
          item.dataset.edenStyled = "message";
        }
      }
    }
  }

  /* ========================================================================= */
  /* 6. iMessage ACTIVE BODY CLASS                                             */
  /* ========================================================================= */

  function isIMessageTabActive() {
    // Check for explicitly styled eden tab
    if (document.querySelector(".eden-imessage-tab.active, .eden-imessage-tab[aria-selected='true']"))
      return true;

    // Fallback: any active tab whose text is "iMessage"
    for (const sel of [
      "[role='tab'][aria-selected='true']",
      "[class*='tab'][class*='active']",
      "button[class*='active']",
    ]) {
      const el = document.querySelector(sel);
      if (el && (el.textContent || "").toLowerCase().includes("imessage")) return true;
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
  /* 7. MUTATION OBSERVER                                                       */
  /* ========================================================================= */

  let _debounce = null;

  function onDOMChange() {
    clearTimeout(_debounce);
    _debounce = setTimeout(() => {
      reorderTabs();
      applyStatusStyling();
      applyIMessageBodyClass();
    }, 150);
  }

  const observer = new MutationObserver(onDOMChange);

  function startObserver() {
    observer.observe(document.body, { childList: true, subtree: true });
    console.log("[EdenBridge] MutationObserver started");
  }

  /* ========================================================================= */
  /* 8. SPA NAVIGATION DETECTION                                               */
  /* ========================================================================= */

  let lastUrl = location.href;

  setInterval(() => {
    if (location.href !== lastUrl) {
      lastUrl = location.href;
      setTimeout(() => {
        reorderTabs();
        autoSelectIMessageTab();
        applyStatusStyling();
      }, 500);
    }
  }, 500);

  // Also hook clicks on conversation list rows
  document.addEventListener("click", (e) => {
    const row = e.target.closest(
      "[class*='conversation-item'], [class*='chat-item'], [class*='contact-item'], [data-conversation-id]"
    );
    if (row) {
      setTimeout(() => {
        reorderTabs();
        autoSelectIMessageTab();
        applyStatusStyling();
      }, 600);
    }
  }, true);

  /* ========================================================================= */
  /* 9. INIT                                                                    */
  /* ========================================================================= */

  function init() {
    injectCSS();
    reorderTabs();
    applyStatusStyling();
    applyIMessageBodyClass();
    startObserver();
    console.log("[EdenBridge] v4.3.0 initialised");
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }

  window.addEventListener("load", () => {
    setTimeout(() => {
      reorderTabs();
      autoSelectIMessageTab();
      applyStatusStyling();
    }, 1000);
  });

  /* ========================================================================= */
  /* 10. DEBUG NAMESPACE                                                        */
  /* ========================================================================= */

  window.EdenBridge = {
    version:              "4.3.0",
    reorderTabs,
    autoSelectIMessageTab,
    applyStatusStyling,
    applyIMessageBodyClass,
    isIMessageTabActive,
  };

})();
