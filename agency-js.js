<script>
(function () {
  "use strict";

  function isIMessageTabActive() {
    var tabs = document.querySelectorAll("[role='tab'], [class*='tab-button'], [class*='channel-tab'], button");
    for (var i = 0; i < tabs.length; i++) {
      var el = tabs[i];
      var text = (el.textContent || "").toLowerCase();
      if (!text.includes("imessage")) continue;
      var isActive = el.classList.contains("active") ||
        el.getAttribute("aria-selected") === "true" ||
        el.closest(".active") !== null;
      if (isActive) {
        el.classList.add("eden-imessage-tab");
        return true;
      }
    }
    return false;
  }

  function applyBodyClass() {
    if (isIMessageTabActive()) {
      document.body.classList.add("eden-imessage-active");
    } else {
      document.body.classList.remove("eden-imessage-active");
    }
  }

  var STATUS_PATTERNS = [
    { test: /^Delivered via iMessage/i, cls: "eden-status-delivered", icon: "✓", color: "#8e8e93" },
    { test: /^Read \d/i,                cls: "eden-status-read",      icon: "✓✓", color: "#007aff" },
    { test: /^Sent as SMS/i,            cls: "eden-status-sms",       icon: "▲", color: "#ff9500" },
    { test: /^Delivered via RCS/i,      cls: "eden-status-rcs",       icon: "⊙", color: "#34c759" }
  ];

  function nukeStyles(el) {
    el.style.setProperty("background", "transparent", "important");
    el.style.setProperty("background-color", "transparent", "important");
    el.style.setProperty("box-shadow", "none", "important");
    el.style.setProperty("border", "none", "important");
    el.style.setProperty("border-radius", "0", "important");
    el.style.setProperty("padding", "0", "important");
    el.style.setProperty("margin", "0", "important");
    el.style.setProperty("min-height", "0", "important");
  }

  function applyStatusStyling() {
    var wrappers = document.querySelectorAll(".messages-single");
    for (var i = 0; i < wrappers.length; i++) {
      var w = wrappers[i];
      if (w.dataset.edenChecked) continue;
      w.dataset.edenChecked = "1";
      var bubble = w.querySelector(".message-bubble, .cnv-message-bubble");
      if (!bubble) continue;
      // Extract just the status text (ignore "Message Details" and other GHL junk)
      var rawText = (bubble.textContent || "").trim();
      
      var match = null;
      var statusText = "";
      for (var j = 0; j < STATUS_PATTERNS.length; j++) {
        var m = rawText.match(STATUS_PATTERNS[j].test);
        if (m) {
          match = STATUS_PATTERNS[j];
          // Extract just the status portion (up to "PM"/"AM")
          var pmIdx = rawText.indexOf("PM");
          var amIdx = rawText.indexOf("AM");
          var endIdx = Math.max(pmIdx, amIdx);
          statusText = endIdx > 0 ? rawText.substring(0, endIdx + 2) : rawText.split("Message")[0].trim();
          // Shorten "Delivered via iMessage" → "iMessage"
          statusText = statusText.replace(/^Delivered via iMessage/i, "iMessage");
          // Shorten "Sent as SMS (contact may not have iMessage)" → "SMS"
          statusText = statusText.replace(/^Sent as SMS[^·]*/i, "SMS ");
          // Shorten "Delivered via RCS" → "RCS"
          statusText = statusText.replace(/^Delivered via RCS/i, "RCS");
          break;
        }
      }
      
      if (!match) continue;
      
      // Add classes
      w.classList.add("eden-status-msg");
      w.classList.add(match.cls);
      
      // NUKE the ENTIRE wrapper — hide everything
      w.innerHTML = "";
      w.style.setProperty("background", "transparent", "important");
      w.style.setProperty("background-color", "transparent", "important");
      w.style.setProperty("box-shadow", "none", "important");
      w.style.setProperty("border", "none", "important");
      w.style.setProperty("border-radius", "0", "important");
      w.style.setProperty("padding", "0", "important");
      // Delivered gets pulled up close to timestamp; Read follows naturally
      var isRead = match.cls === "eden-status-read";
      w.style.setProperty("margin", isRead ? "-2px 0 0 0" : "-14px 0 0 0", "important");
      w.style.setProperty("min-height", "0", "important");
      w.style.setProperty("max-height", "16px", "important");
      w.style.setProperty("height", "16px", "important");
      w.style.setProperty("overflow", "hidden", "important");
      w.style.setProperty("display", "flex", "important");
      w.style.setProperty("justify-content", "flex-end", "important");
      w.style.setProperty("align-items", "center", "important");
      w.style.setProperty("padding-right", "12px", "important");
      
      // Create clean indicator
      var span = document.createElement("span");
      span.textContent = match.icon + " " + statusText;
      span.style.setProperty("font-size", "10px", "important");
      span.style.setProperty("color", match.color, "important");
      span.style.setProperty("font-family", "-apple-system, BlinkMacSystemFont, system-ui, sans-serif", "important");
      span.style.setProperty("font-weight", "400", "important");
      span.style.setProperty("line-height", "16px", "important");
      span.style.setProperty("white-space", "nowrap", "important");
      w.appendChild(span);
    }
  }

  var debounce = null;
  function onDOMChange() {
    clearTimeout(debounce);
    debounce = setTimeout(function () {
      applyStatusStyling();
      applyBodyClass();
    }, 200);
  }

  var lastUrl = location.href;
  setInterval(function () {
    if (location.href !== lastUrl) {
      lastUrl = location.href;
      setTimeout(function () { applyStatusStyling(); applyBodyClass(); }, 600);
    }
  }, 500);

  document.addEventListener("click", function (e) {
    var row = e.target.closest("[class*='conversation-item'], [class*='chat-item'], [data-conversation-id]");
    if (row) {
      setTimeout(function () { applyStatusStyling(); applyBodyClass(); }, 700);
    }
  }, true);

  function init() {
    applyStatusStyling();
    applyBodyClass();
    var observer = new MutationObserver(onDOMChange);
    observer.observe(document.body, { childList: true, subtree: true });
    console.log("[EdenBridge] v2.2 initialized");
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }

  window.addEventListener("load", function () {
    setTimeout(function () { applyStatusStyling(); applyBodyClass(); }, 1000);
  });
})();
</script>
