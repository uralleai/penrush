/* ==========================================================================
   PenRUSH download site — gate + OS-aware download logic
   Vanilla JS. Zero dependencies. Zero telemetry. Zero network calls.
   Nothing here phones home, sets a cookie, or stores anything. OS detection
   is a pure, synchronous read of navigator.userAgent / navigator.platform —
   no request is made, nothing is transmitted or persisted. The consent
   affirmation is content-based per CTO arch §E.1 — checked enables the
   control; nothing is transmitted or persisted.
   ========================================================================== */
(function () {
  "use strict";

  /* ----------------------------------------------------------------------
     GO-LIVE CONSTANTS — HARDCODED on purpose (security INFO-2).
     These are NEVER derived from the query string, location, referrer, or any
     other runtime input: a runtime-sourced download base is an open-redirect /
     asset-swap vector (a hostile ?base=… could point "Download" at malware).
     The signed v0.1.0 release is public, so the gate is open. To re-gate,
     flip RELEASE_AVAILABLE back to false — no other change needed.
     ---------------------------------------------------------------------- */
  var RELEASE_AVAILABLE = true;
  var RELEASE_BASE_URL  = "https://github.com/uralleai/penrush/releases/download/v0.1.0/";
  var RELEASE_TAG       = "v0.1.0";

  /* The release "all assets" page — every OS/arch binary + checksums.txt +
     cosign bundle + SLSA provenance. Hardcoded, same rationale as above. */
  var RELEASE_PAGE_URL  = "https://github.com/uralleai/penrush/releases/tag/v0.1.0";

  /* The tagged, immutable verification runbook on GitHub (always resolves). */
  var RELEASE_DOC_URL   = "https://github.com/uralleai/penrush/blob/v0.1.0/docs/RELEASE.md";

  /* Published binaries for v0.1.0. Names MUST match the release assets exactly
     (verified against the release: penrush-{linux,darwin,windows}-{amd64,arm64};
     the Windows asset has no .exe suffix). JS can only resolve the amd64 build
     for the detected OS — see detectPlatform(). */
  var ARTIFACTS = {
    windows: "penrush-windows-amd64",
    darwin:  "penrush-darwin-amd64",
    linux:   "penrush-linux-amd64"
  };

  /* Client-side OS detection ONLY. No network, no storage, no telemetry — a
     synchronous read of two navigator strings. JS cannot reliably distinguish
     amd64 from arm64, so we resolve to the amd64 build for the detected OS and
     steer everyone (especially Apple-Silicon / arm64 users) to the always-
     visible "All platforms" link for the exact right binary + verification. */
  function detectPlatform() {
    var hay = ((navigator.userAgent || "") + " " + (navigator.platform || "")).toLowerCase();
    if (hay.indexOf("win") !== -1) {
      return { artifact: ARTIFACTS.windows, label: "Windows", arch: "64-bit Intel/AMD (x86-64)" };
    }
    if (hay.indexOf("mac") !== -1 || hay.indexOf("darwin") !== -1) {
      return { artifact: ARTIFACTS.darwin, label: "macOS", arch: "Intel build — on Apple Silicon use All platforms" };
    }
    return { artifact: ARTIFACTS.linux, label: "Linux", arch: "64-bit Intel/AMD (x86-64)" };
  }

  var plat = detectPlatform();

  var btn          = document.getElementById("download-btn");
  var consent      = document.getElementById("consent");
  var hint         = document.getElementById("consent-hint");
  var statusText   = document.getElementById("gate-status-text");
  var docLink      = document.getElementById("release-doc-link");
  var artifactNote = document.getElementById("artifact-note");
  var artifactName = document.getElementById("artifact-name");
  var artifactArch = document.getElementById("artifact-arch");

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
      /* Re-gate path: flip RELEASE_AVAILABLE back to false to pause downloads.
         Button stays inert regardless of the consent box. The always-visible
         "All platforms" link (static HTML) still points at the release page. */
      disableBtn("Downloads paused");
      if (artifactNote) { artifactNote.hidden = true; }
      hint.textContent = consent.checked
        ? "Consent recorded. Direct downloads are paused right now."
        : "";
      return;
    }

    /* Live path — the signed v0.1.0 release is public. */
    if (statusText) { statusText.textContent = "Latest release " + RELEASE_TAG; }
    if (docLink)    { docLink.setAttribute("href", RELEASE_DOC_URL); docLink.removeAttribute("aria-disabled"); }

    /* Show exactly which file the OS-detected button resolves to. */
    if (artifactNote && artifactName) {
      artifactName.textContent = plat.artifact;
      if (artifactArch) { artifactArch.textContent = plat.arch; }
      artifactNote.hidden = false;
    }

    var label = "Download for " + plat.label;

    /* Button gated on consent only (release is live). */
    if (consent.checked) {
      enableBtn(RELEASE_BASE_URL + plat.artifact, label);
      hint.textContent = "";
    } else {
      disableBtn(label);
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
