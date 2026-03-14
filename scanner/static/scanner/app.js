const urlInput = document.getElementById("url");
const resultEl = document.getElementById("result");
const scanBtn = document.getElementById("scanBtn");
const clearBtn = document.getElementById("clearBtn");

function escapeHtml(s){
  return String(s)
    .replaceAll("&","&amp;")
    .replaceAll("<","&lt;")
    .replaceAll(">","&gt;");
}

function uiForState(stateRaw, backendConfidence){
  const state = String(stateRaw || "").toUpperCase();
  const confidence = backendConfidence || (state === "UNSAFE" ? "High" : "Medium");

  if(state === "UNSAFE"){
    return {
      tone: "no",
      pill: "UNSAFE",
      headline: "Likely phishing. Avoid this link.",
      action: "Close the page. Do not enter any information.",
      steps: [
        "Do not log in or pay on this site.",
        "If you already entered details, change your password.",
        "If this came from someone you know, confirm separately."
      ],
      confidence
    };
  }

  if(state === "BE_CAREFUL"){
    return {
      tone: "careful",
      pill: "SUSPICIOUS",
      headline: "Something looks off.",
      action: "Do not enter passwords or payment details until you verify it.",
      steps: [
        "Search the company name yourself.",
        "Check the web address carefully.",
        "If unsure, leave the page."
      ],
      confidence
    };
  }

  return {
    tone: "ok",
    pill: "SAFE",
    headline: "No known signs of phishing.",
    action: "Still double check before logging in.",
    steps: [
      "Only continue if you expected the link.",
      "Use bookmarks for banking.",
      "Leave the page if anything feels wrong."
    ],
    confidence
  };
}

function topReasons(data){
  const reasons = [];
  const raw = data?.reasons || {};

  for(const key of Object.keys(raw)){
    const value = raw[key];

    if(key === "safe_browsing"){
      reasons.push("A trusted safety service has flagged this link as risky.");
      continue;
    }

    if(key === "openphish"){
      reasons.push("This link matches a known phishing list.");
      continue;
    }

    if(key === "tls"){
      reasons.push("This site does not appear securely configured.");
      continue;
    }

    if(key === "heuristics"){
      if(Array.isArray(value)){
        for(const r of value){
          const rr = String(r || "").toLowerCase();

          if(rr.includes("long url")) {
            reasons.push("The web address is unusually long.");
          } else if(rr.includes("subdomain")) {
            reasons.push("The web address uses an unusual structure.");
          } else if(rr.includes("ip address")) {
            reasons.push("The link uses an IP address instead of a normal website name.");
          } else if(rr.includes("punycode")) {
            reasons.push("The website name may be hiding lookalike characters.");
          } else {
            reasons.push("The web address shows suspicious signs.");
          }
        }
      }
    }
  }

  return [...new Set(reasons)].slice(0, 3);
}

function riskLabel(state){
  if(state === "UNSAFE") return "High risk";
  if(state === "BE_CAREFUL") return "Medium risk";
  return "Low risk";
}

function toggle(el, btn, show, hide){
  const open = el.style.display !== "none";
  el.style.display = open ? "none" : "block";
  btn.textContent = open ? show : hide;
}

function renderResult(data){
  const card = uiForState(data?.state, data?.confidence);
  const reasons = topReasons(data);
  const reasonsHtml = reasons.length
    ? reasons.map(r => `<li>${escapeHtml(r)}</li>`).join("")
    : "<li>No extra details were returned for this result.</li>";

  resultEl.className = `card result ${card.tone}`;

  resultEl.innerHTML = `
<div class="resultTop">

  <div class="statusPill ${card.tone}">
    <span class="dot"></span>
    <span>${card.pill}</span>
  </div>

  <div class="meta">
    <div>Risk: <span class="metaValue">${riskLabel(data?.state)}</span></div>
    <div>Confidence: <span class="metaValue">${escapeHtml(card.confidence)}</span></div>
    <div>Score: <span class="metaValue">${Number.isFinite(data?.score) ? data.score : "-"}/100</span></div>
  </div>

</div>

<h2 class="headline">${card.headline}</h2>

<div class="checkedUrl">
  <strong>Checked link:</strong> ${escapeHtml(data?.url || "")}
</div>

<p class="action">${card.action}</p>

<div class="actionBox">
  <strong>What you should do</strong>
  <ul class="list">${card.steps.map(s => `<li>${escapeHtml(s)}</li>`).join("")}</ul>
</div>

<div class="panel">
  <button class="linkBtn" id="whyBtn" type="button">Why WebSense flagged this</button>
  <div id="whyWrap" style="display:none">
    <ul>${reasonsHtml}</ul>
  </div>
</div>
`;

  const whyBtn = document.getElementById("whyBtn");
  const whyWrap = document.getElementById("whyWrap");

  whyBtn.onclick = () => toggle(whyWrap, whyBtn, "Why WebSense flagged this", "Hide explanation");

  resultEl.style.display = "block";
}

function renderChecking(){
  resultEl.className = "card result careful";
  resultEl.innerHTML = `
<div class="statusPill careful">
  <span class="dot"></span>
  <span>CHECKING</span>
</div>

<h2 class="headline">Checking link...</h2>

<div class="loadingWrap">
  <div class="spinner"></div>
  <div class="loadingText">
    Scanning the link for phishing signals and security issues.
  </div>
</div>
`;
  resultEl.style.display = "block";
}

function renderError(msg){
  resultEl.className = "card result no";
  resultEl.innerHTML = `
<div class="statusPill no">
  <span class="dot"></span>
  <span>ERROR</span>
</div>

<h2 class="headline">${escapeHtml(msg)}</h2>
<p class="action">Try again with a full link like https://example.com</p>
`;
  resultEl.style.display = "block";
}

function isValidHttpUrl(value){
  try {
    const parsed = new URL(value);
    return parsed.protocol === "http:" || parsed.protocol === "https:";
  } catch {
    return false;
  }
}

async function readErrorResponse(res){
  const contentType = res.headers.get("content-type") || "";

  if(contentType.includes("application/json")){
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

async function handleScan(urlOverride = null){
  const rawUrl = urlOverride ?? urlInput.value;
  const url = String(rawUrl || "").trim();

  if(!url){
    renderError("Please enter a website link.");
    urlInput.focus();
    return;
  }

  if(!isValidHttpUrl(url)){
    renderError("Enter a full website link starting with http:// or https://");
    urlInput.focus();
    return;
  }

  urlInput.value = url;
  scanBtn.disabled = true;
  renderChecking();

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 12000);

    const res = await fetch("/api/scan/", {
      method: "POST",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify({ url }),
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    if(!res.ok){
      const message = await readErrorResponse(res);
      renderError(message);
      return;
    }

    const contentType = res.headers.get("content-type") || "";

    if(!contentType.includes("application/json")){
      renderError("The server returned an unexpected response.");
      return;
    }

    const data = await res.json();
    renderResult(data);

  } catch(err) {
    if(err.name === "AbortError"){
      renderError("The scan took too long. Please try again.");
      return;
    }

    renderError("Could not connect to the scanner. Please try again.");
  } finally {
    scanBtn.disabled = false;
  }
}

function handleClear(){
  urlInput.value = "";
  resultEl.style.display = "none";
  resultEl.innerHTML = "";
  resultEl.className = "card";
  scanBtn.disabled = false;

  const cleanUrl = window.location.pathname;
  window.history.replaceState({}, "", cleanUrl);
}

function loadUrlFromQuery(){
  const params = new URLSearchParams(window.location.search);
  const urlFromQuery = params.get("url");

  if(!urlFromQuery){
    return;
  }

  const decodedUrl = decodeURIComponent(urlFromQuery).trim();

  if(!decodedUrl){
    return;
  }

  urlInput.value = decodedUrl;
  handleScan(decodedUrl);
}

scanBtn.addEventListener("click", () => handleScan());
clearBtn.addEventListener("click", handleClear);

urlInput.addEventListener("keydown", (e) => {
  if(e.key === "Enter") handleScan();
});

document.addEventListener("DOMContentLoaded", loadUrlFromQuery);