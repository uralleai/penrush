/* ==========================================================================
   PenRUSH download site — gate logic
   Vanilla JS. Zero dependencies. Zero telemetry. Zero network calls.
   Nothing here phones home, sets a cookie, or stores anything. The consent
   affirmation is content-based per CTO arch §E.1 — checked enables the
   control; nothing is transmitted or persisted.
   ========================================================================== */
(function () {
  "use strict";

  /* ----------------------------------------------------------------------
     BUILD-TIME FLAG — the one line to flip when PH-2 clears.
     While false, downloads are gated regardless of the consent checkbox.
     To go live:
       1. set RELEASE_AVAILABLE = true
       2. set RELEASE_BASE_URL to the immutable GitHub Releases asset base,
          e.g. "https://github.com/OWNER/REPO/releases/download/v0.1.0/"
     No other code change is required. (No real binary URL is live yet —
     the signed release needs the public repo + push, which is PH-2-gated.)
     ---------------------------------------------------------------------- */
  var RELEASE_AVAILABLE = false;
  var RELEASE_BASE_URL  = "";          // filled in at the same time as the flag
  var RELEASE_TAG       = "";          // e.g. "v0.1.0" — shown in the live button

  /* The default artifact a generic "Download" button points at. Platform
     pickers can be added later; v1 keeps this honest and simple. */
  var DEFAULT_ARTIFACT  = "penrush-linux-amd64";

  var btn        = document.getElementById("download-btn");
  var consent    = document.getElementById("consent");
  var hint       = document.getElementById("consent-hint");
  var statusText = document.getElementById("gate-status-text");
  var gateNote   = document.getElementById("gate-note");
  var docLink    = document.getElementById("release-doc-link");

  if (!btn || !consent) { return; }

  function enableBtn(href, label) {
    btn.setAttribute("href", href);
    btn.setAttribute("aria-disabled", "false");
    btn.removeAttribute("tabindex");
    btn.textContent = label;
  }

  function disableBtn(label) {
    btn.setAttribute("href", "#download");
    btn.setAttribute("aria-disabled", "true");
    btn.setAttribute("tabindex", "-1");
    btn.textContent = label;
  }

  function render() {
    if (!RELEASE_AVAILABLE) {
      /* Hard gate: audit not cleared. Button stays inert no matter the box. */
      disableBtn("Download — awaiting security audit");
      hint.textContent = consent.checked
        ? "Consent recorded. Downloads open when the security audit clears."
        : "";
      return;
    }

    /* Live path (post-PH-2). Button gated on consent only. */
    if (statusText) { statusText.textContent = "Latest release " + (RELEASE_TAG || "available"); }
    if (gateNote)   { gateNote.hidden = true; }
    if (docLink)    { docLink.setAttribute("href", "docs/RELEASE.md"); docLink.removeAttribute("aria-disabled"); }

    if (consent.checked) {
      enableBtn(RELEASE_BASE_URL + DEFAULT_ARTIFACT, "Download PenRUSH " + (RELEASE_TAG || ""));
      hint.textContent = "";
    } else {
      disableBtn("Download PenRUSH");
      hint.textContent = "Accept the license and terms above to enable the download.";
    }
  }

  /* Block clicks while the button is disabled (it is an <a> for styling). */
  btn.addEventListener("click", function (e) {
    if (btn.getAttribute("aria-disabled") === "true") {
      e.preventDefault();
      if (!consent.checked && RELEASE_AVAILABLE) {
        consent.focus();
        hint.textContent = "Accept the license and terms above to enable the download.";
      }
    }
  });

  consent.addEventListener("change", render);
  render();
})();
