const urlInput = document.getElementById("url");
const resultEl = document.getElementById("result");
const scanBtn = document.getElementById("scanBtn");
const clearBtn = document.getElementById("clearBtn");

// Escape text before putting it into HTML
function escapeHtml(s) {
  return String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

// Pick wording based on final state
function uiForState(stateRaw) {
  const state = String(stateRaw || "").toUpperCase();

  if (state === "UNSAFE") {
    return {
      tone: "no",
      pill: "UNSAFE",
      headline: "This link looks dangerous.",
      action: "Do not use this website or enter any personal information.",
      steps: [
        "Leave the page now.",
        "Do not log in or make any payment.",
        "If you already entered details, change your password as soon as possible."
      ]
    };
  }

  if (state === "BE_CAREFUL") {
    return {
      tone: "careful",
      pill: "BE CAREFUL",
      headline: "This link may not be safe.",
      action: "Do not enter passwords or payment details until you verify it.",
      steps: [
        "Check the web address carefully.",
        "Search for the company or service yourself.",
        "If you are unsure, leave the page."
      ]
    };
  }

  return {
    tone: "ok",
    pill: "SAFE",
    headline: "No clear warning signs were found.",
    action: "You can continue, but still double check before entering personal information.",
    steps: [
      "Only continue if you expected this link.",
      "Use bookmarks for important websites.",
      "Leave the page if anything feels wrong."
    ]
  };
}

// Turn technical reasons into plain English
function topReasons(data) {
  const reasons = [];
  const raw = data?.reasons || {};

  for (const key of Object.keys(raw)) {
    const value = raw[key];

    if (key === "safe_browsing") {
      reasons.push("A trusted safety service flagged this link as risky.");
      continue;
    }

    if (key === "openphish") {
      reasons.push("This link matches a known list of unsafe websites.");
      continue;
    }

    if (key === "tls") {
      reasons.push("This website does not appear securely configured.");
      continue;
    }

    if (key === "tls_expiry_soon") {
      reasons.push("This website’s security certificate is close to expiring.");
      continue;
    }

    if (key === "tls_expired") {
      reasons.push("This website’s security certificate has expired.");
      continue;
    }

    if (key === "heuristics" && Array.isArray(value)) {
      for (const r of value) {
        const rr = String(r || "").toLowerCase();

        if (rr.includes("long url")) {
          reasons.push("The web address is unusually long.");
        } else if (rr.includes("subdomain")) {
          reasons.push("The web address uses an unusual structure.");
        } else if (rr.includes("ip address")) {
          reasons.push("The link uses numbers instead of a normal website name.");
        } else if (rr.includes("punycode")) {
          reasons.push("The website name may be hiding lookalike characters.");
        } else if (rr.includes("brand")) {
          reasons.push("The website name may be pretending to be a well-known brand.");
        } else if (rr.includes("keyword")) {
          reasons.push("The web address contains words often seen in scam links.");
        } else {
          reasons.push("The web address shows warning signs.");
        }
      }
    }
  }

  // Remove duplicates and only keep the first 3
  return [...new Set(reasons)].slice(0, 3);
}

// Extra small notes, like cached results
function extraInfo(data) {
  const bits = [];

  if (data?.cached === true) {
    bits.push("Showing a recent saved result.");
  }

  return bits;
}

// Show or hide an expandable section
function toggle(el, btn, show, hide) {
  const open = el.style.display !== "none";
  el.style.display = open ? "none" : "block";
  btn.textContent = open ? show : hide;
}

// Show the final result card
function renderResult(data) {
  const card = uiForState(data?.state);
  const reasons = topReasons(data);
  const info = extraInfo(data);

  const reasonsHtml = reasons.length
    ? reasons.map(r => `<p class="explanationLine">${escapeHtml(r)}</p>`).join("")
    : `<p class="explanationLine">No extra details were returned for this result.</p>`;

  const infoHtml = info.length
    ? info.map(x => `<p class="noteText">${escapeHtml(x)}</p>`).join("")
    : "";

  resultEl.className = `card result ${card.tone}`;

  resultEl.innerHTML = `
    <div class="resultTop">
      <div class="statusPill ${card.tone}">
        <span class="dot"></span>
        <span>${card.pill}</span>
      </div>
    </div>

    <h2 class="headline">${card.headline}</h2>

    <div class="checkedUrl">
      <strong>Checked link:</strong>
      <span class="checkedUrlText">${escapeHtml(data?.url || "")}</span>
    </div>

    <p class="actionText">${card.action}</p>

    ${infoHtml}

    <div class="actionBox">
      <strong>What you should do</strong>
      <ul class="list">
        ${card.steps.map(s => `<li>${escapeHtml(s)}</li>`).join("")}
      </ul>
    </div>

    <div class="whySection">
      <a href="#" class="linkBtn" id="whyBtn">Show explanation</a>
      <div id="whyWrap" class="whyWrap" style="display:none">
        ${reasonsHtml}
      </div>
    </div>
  `;

  const whyBtn = document.getElementById("whyBtn");
  const whyWrap = document.getElementById("whyWrap");

  whyBtn.onclick = (e) => {
    e.preventDefault();
    toggle(whyWrap, whyBtn, "Show explanation", "Hide explanation");
  };

  resultEl.style.display = "block";
}

// Show loading state while scan runs
function renderChecking() {
  resultEl.className = "card result careful";
  resultEl.innerHTML = `
    <div class="statusPill careful">
      <span class="dot"></span>
      <span>CHECKING</span>
    </div>

    <h2 class="headline">Checking this link...</h2>

    <div class="loadingWrap">
      <div class="spinner"></div>
      <div class="loadingText">
        Checking this link for warning signs.
      </div>
    </div>
  `;
  resultEl.style.display = "block";
}

// Show an error card
function renderError(msg) {
  resultEl.className = "card result no";
  resultEl.innerHTML = `
    <div class="statusPill no">
      <span class="dot"></span>
      <span>ERROR</span>
    </div>

    <h2 class="headline">${escapeHtml(msg)}</h2>
    <p class="actionText">Try again with a full website link, for example https://example.com</p>
  `;
  resultEl.style.display = "block";
}

// Basic frontend URL check
function isValidHttpUrl(value) {
  try {
    const parsed = new URL(value);
    return parsed.protocol === "http:" || parsed.protocol === "https:";
  } catch {
    return false;
  }
}

// Read backend error nicely
async function readErrorResponse(res) {
  const contentType = res.headers.get("content-type") || "";

  if (contentType.includes("application/json")) {
    const data = await res.json();
    return (
      data?.error ||
      data?.message ||
      data?.detail ||
      data?.explanation ||
      `The server returned ${res.status}.`
    );
  }

  const text = await res.text();
  return text?.trim() || `The server returned ${res.status}.`;
}

// Main scan function
async function handleScan(urlOverride = null) {
  const rawUrl = urlOverride ?? urlInput.value;
  const url = String(rawUrl || "").trim();

  if (!url) {
    renderError("Please enter a website link.");
    urlInput.focus();
    return;
  }

  if (!isValidHttpUrl(url)) {
    renderError("Enter a full website link starting with http:// or https://");
    urlInput.focus();
    return;
  }

  urlInput.value = url;
  scanBtn.disabled = true;
  renderChecking();

  try {
    // Stop request if it takes too long
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 12000);

    const res = await fetch("/api/scan/", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    if (!res.ok) {
      const message = await readErrorResponse(res);
      renderError(message);
      return;
    }

    const contentType = res.headers.get("content-type") || "";

    if (!contentType.includes("application/json")) {
      renderError("The server returned an unexpected response.");
      return;
    }

    const data = await res.json();
    renderResult(data);
  } catch (err) {
    if (err.name === "AbortError") {
      renderError("The scan took too long. Please try again.");
      return;
    }

    renderError("Could not connect to the scanner. Please try again.");
  } finally {
    scanBtn.disabled = false;
  }
}

// Clear the form and result
function handleClear() {
  urlInput.value = "";
  resultEl.style.display = "none";
  resultEl.innerHTML = "";
  resultEl.className = "card";
  scanBtn.disabled = false;

  const cleanUrl = window.location.pathname;
  window.history.replaceState({}, "", cleanUrl);
}

// Load URL from query string if present
function loadUrlFromQuery() {
  const params = new URLSearchParams(window.location.search);
  const urlFromQuery = params.get("url");

  if (!urlFromQuery) {
    return;
  }

  const decodedUrl = decodeURIComponent(urlFromQuery).trim();

  if (!decodedUrl) {
    return;
  }

  urlInput.value = decodedUrl;
  handleScan(decodedUrl);
}

// Button clicks
scanBtn.addEventListener("click", () => handleScan());
clearBtn.addEventListener("click", handleClear);

// Enter key support
urlInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") {
    handleScan();
  }
});

// Run query string check on page load
document.addEventListener("DOMContentLoaded", loadUrlFromQuery);