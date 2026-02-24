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
          // Shorten status text
          if (match.cls === "eden-status-delivered") {
            statusText = "iMessage";
          } else if (match.cls === "eden-status-rcs") {
            statusText = "RCS";
          } else if (match.cls === "eden-status-sms") {
            statusText = "SMS";
          } else if (match.cls === "eden-status-read") {
            // Keep read time since it differs from send time
            var pmIdx = rawText.indexOf("PM");
            var amIdx = rawText.indexOf("AM");
            var endIdx = Math.max(pmIdx, amIdx);
            statusText = endIdx > 0 ? "Read " + rawText.match(/\d{1,2}:\d{2}\s*[AP]M/i)?.[0] : "Read";
          }
          break;
        }
      }
      
      if (!match) continue;
      
      // Check if next sibling is a Read status — if so, merge into one line
      var mergedReadText = "";
      if (match.cls !== "eden-status-read") {
        var next = w.nextElementSibling;
        if (next && !next.dataset.edenChecked) {
          var nextBubble = next.querySelector(".message-bubble, .cnv-message-bubble");
          if (nextBubble) {
            var nextRaw = (nextBubble.textContent || "").trim();
            if (/^Read \d/i.test(nextRaw)) {
              // Extract read time
              var readTimeMatch = nextRaw.match(/\d{1,2}:\d{2}\s*[AP]M/i);
              mergedReadText = readTimeMatch ? "Read " + readTimeMatch[0] : "Read";
              // Hide the next row entirely
              next.dataset.edenChecked = "1";
              next.innerHTML = "";
              next.style.setProperty("display", "none", "important");
            }
          }
        }
      }
      
      // If this IS a read row and wasn't already merged, show standalone
      if (match.cls === "eden-status-read" && !mergedReadText) {
        var readTimeMatch2 = rawText.match(/\d{1,2}:\d{2}\s*[AP]M/i);
        statusText = readTimeMatch2 ? "Read " + readTimeMatch2[0] : "Read";
      }
      
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
      w.style.setProperty("margin", "-28px 0 0 0", "important");
      w.style.setProperty("min-height", "0", "important");
      w.style.setProperty("max-height", "16px", "important");
      w.style.setProperty("height", "16px", "important");
      w.style.setProperty("overflow", "hidden", "important");
      w.style.setProperty("display", "flex", "important");
      w.style.setProperty("justify-content", "flex-end", "important");
      w.style.setProperty("align-items", "center", "important");
      w.style.setProperty("padding-right", "42px", "important");
      
      // Build the combined line
      var span = document.createElement("span");
      var displayText = match.icon + " " + statusText;
      if (mergedReadText) {
        displayText += "  ✓✓ " + mergedReadText;
      }
      span.style.setProperty("font-size", "10px", "important");
      span.style.setProperty("font-family", "-apple-system, BlinkMacSystemFont, system-ui, sans-serif", "important");
      span.style.setProperty("font-weight", "400", "important");
      span.style.setProperty("line-height", "16px", "important");
      span.style.setProperty("white-space", "nowrap", "important");
      
      // Flex column layout — two lines stacked
      w.style.setProperty("flex-direction", "column", "important");
      w.style.setProperty("align-items", "flex-end", "important");
      w.style.setProperty("justify-content", "center", "important");
      
      var s1 = document.createElement("span");
      s1.textContent = match.icon + " " + statusText;
      s1.style.setProperty("color", match.color, "important");
      s1.style.setProperty("font-size", "10px", "important");
      s1.style.setProperty("white-space", "nowrap", "important");
      s1.style.setProperty("font-family", "-apple-system, BlinkMacSystemFont, system-ui, sans-serif", "important");
      s1.style.setProperty("margin-right", "50px", "important");
      s1.style.setProperty("line-height", "14px", "important");
      w.appendChild(s1);
      
      if (mergedReadText) {
        var s2 = document.createElement("span");
        s2.textContent = "✓✓ " + mergedReadText;
        s2.style.setProperty("color", "#007aff", "important");
        s2.style.setProperty("font-size", "10px", "important");
        s2.style.setProperty("white-space", "nowrap", "important");
        s2.style.setProperty("font-family", "-apple-system, BlinkMacSystemFont, system-ui, sans-serif", "important");
        s2.style.setProperty("margin-right", "30px", "important");
        s2.style.setProperty("line-height", "14px", "important");
        w.appendChild(s2);
        w.style.setProperty("max-height", "32px", "important");
        w.style.setProperty("height", "32px", "important");
      }
      
      if (!mergedReadText && match.cls === "eden-status-read") {
        s1.style.setProperty("margin-right", "30px", "important");
      }
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
    console.log("[EdenBridge] v2.8 initialized");
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
