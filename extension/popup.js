const API_BASE = "https://websense-1ic6.onrender.com";
const API_SCAN_URL = `${API_BASE}/api/scan/`;
const WEBAPP_URL = `${API_BASE}/`;

const currentUrlEl = document.getElementById("current-url");
const scanBtn = document.getElementById("scan-btn");
const loadingEl = document.getElementById("loading");
const resultEl = document.getElementById("result");
const stateBadgeEl = document.getElementById("state-badge");
const confidenceEl = document.getElementById("confidence");
const explanationEl = document.getElementById("explanation");
const errorEl = document.getElementById("error");
const openSiteBtn = document.getElementById("open-site-btn");
const resultTitleEl = document.getElementById("result-title");

let currentTabUrl = "";

function showError(message) {
  errorEl.textContent = message;
  errorEl.classList.remove("hidden");
}

function hideError() {
  errorEl.textContent = "";
  errorEl.classList.add("hidden");
}

function showLoading() {
  loadingEl.classList.remove("hidden");
}

function hideLoading() {
  loadingEl.classList.add("hidden");
}

function hideResult() {
  resultEl.classList.add("hidden");
  resultEl.classList.remove("safe", "careful", "unsafe");
  stateBadgeEl.textContent = "-";
  stateBadgeEl.className = "badge";
  confidenceEl.textContent = "-";
  explanationEl.textContent = "-";
  resultTitleEl.textContent = "Result";
}

function getResultTitle(state) {
  if (state === "SAFE") return "No known signs of phishing.";
  if (state === "BE CAREFUL") return "Some warning signs were found.";
  if (state === "UNSAFE") return "This website looks unsafe.";
  return "Result";
}

function showResult(data) {
  const state = (data.state || "UNKNOWN").toUpperCase();
  const confidence = data.confidence || "Unknown";
  const explanation = data.explanation || "No explanation returned.";

  stateBadgeEl.textContent = state;
  stateBadgeEl.className = "badge";
  resultEl.classList.remove("safe", "careful", "unsafe");

  if (state === "SAFE") {
    stateBadgeEl.classList.add("safe");
    resultEl.classList.add("safe");
  } else if (state === "BE CAREFUL") {
    stateBadgeEl.classList.add("careful");
    resultEl.classList.add("careful");
  } else if (state === "UNSAFE") {
    stateBadgeEl.classList.add("unsafe");
    resultEl.classList.add("unsafe");
  }

  confidenceEl.textContent = String(confidence).toLowerCase();
  explanationEl.textContent = explanation;
  resultTitleEl.textContent = getResultTitle(state);
  resultEl.classList.remove("hidden");
}

function isScannableUrl(url) {
  return url.startsWith("http://") || url.startsWith("https://");
}

async function getCurrentTabUrl() {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });

  if (!tabs || !tabs.length) {
    throw new Error("Could not read the current tab.");
  }

  const tab = tabs[0];

  if (!tab.url) {
    throw new Error("Current tab has no readable URL.");
  }

  return tab.url;
}

async function scanUrl(url) {
  const response = await fetch(API_SCAN_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ url })
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`Scan failed: ${response.status} ${text}`);
  }

  return response.json();
}

async function runScan() {
  hideError();
  hideResult();

  if (!currentTabUrl || !isScannableUrl(currentTabUrl)) {
    showError("No valid website URL found.");
    return;
  }

  try {
    showLoading();
    const data = await scanUrl(currentTabUrl);
    showResult(data);
  } catch (error) {
    showError(error.message || "Something went wrong while scanning.");
  } finally {
    hideLoading();
  }
}

async function initialisePopup() {
  hideError();
  hideResult();

  try {
    currentTabUrl = await getCurrentTabUrl();

    if (!isScannableUrl(currentTabUrl)) {
      currentUrlEl.textContent = "Unsupported page";
      scanBtn.disabled = true;
      scanBtn.textContent = "Cannot scan this page";
      showError("This page cannot be scanned. Try a normal website.");
      return;
    }

    const urlObj = new URL(currentTabUrl);
    currentUrlEl.textContent = urlObj.hostname;

    await runScan();
  } catch (error) {
    currentUrlEl.textContent = "Unable to detect current tab.";
    showError(error.message || "Failed to scan this website.");
  }
}

scanBtn.addEventListener("click", async () => {
  await runScan();
});

openSiteBtn.addEventListener("click", () => {
  const target = currentTabUrl
    ? `${WEBAPP_URL}?url=${encodeURIComponent(currentTabUrl)}`
    : WEBAPP_URL;

  chrome.tabs.create({ url: target });
});

initialisePopup();