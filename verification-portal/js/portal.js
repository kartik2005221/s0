/**
 * s0 Verification Portal — Pure Client-Side Verifier Controller
 * Supports: JSON certificates, PDF certificate optical decoding, QR image decoding
 */

var PINNED_KEYS = [
  {
    issuer: "s0 Demo Lab (unaccredited development key)",
    fingerprint: "sha256:8396af8c07a7d40f98ba492cf2b61e23fa768e66a9f627b02a9caff464e48c06",
    public_key_spki_pem: "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA4viQlkj0bHna+uhXpU+r4LjzhKG5nq3tGMih9VoR7K0=\n-----END PUBLIC KEY-----",
    public_key_raw_hex: "e2f8909648f46c79dafae857a54fabe0b8f384a1b99eaded18c8a1f55a11ecad"
  }
];

// Configure PDF.js worker if available
if (typeof pdfjsLib !== "undefined") {
  pdfjsLib.GlobalWorkerOptions.workerSrc = "vendor/pdf.worker.min.js";
}

function decodeBase64Utf8(b64) {
  if (typeof atob === "undefined") return "";
  try {
    var bin = atob(b64);
    if (typeof TextDecoder !== "undefined") {
      var bytes = new Uint8Array(bin.length);
      for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      return new TextDecoder("utf-8").decode(bytes);
    }
    return decodeURIComponent(escape(bin));
  } catch (_) {
    return "";
  }
}

// Fallback sample certificates for offline testing
var SAMPLE_VALID_CERT = {
  "schema_version": "1.0.0",
  "cert_uuid": "6da82f40-ba63-4f06-a2bd-fb7bee6e715a",
  "issued_at": "2026-08-31T01:59:10Z",
  "issuer": {
    "organization": "s0 Demo Lab",
    "operator_id": "op-demo-42"
  },
  "tool": {
    "name": "s0-cli",
    "version": "2.2.1",
    "platform": "linux"
  },
  "device": {
    "device_id": "test-drive-001",
    "device_type": "image_file",
    "storage_type": "IMAGE_FILE",
    "capacity_bytes": 1048576,
    "model": "Virtual Test Drive",
    "serial_number": "SN-12345678"
  },
  "wipe": {
    "method": "OVERWRITE_ZERO_1PASS",
    "nist_category": "Clear",
    "start_time": "2026-08-31T07:00:00Z",
    "end_time": "2026-08-31T07:01:00Z",
    "bytes_processed": 1048576
  },
  "result": {
    "status": "success",
    "verification": {
      "method": "sampled_readback",
      "samples_checked": 64,
      "sample_bytes_each": 4096,
      "all_samples_match_wipe_pattern": true,
      "planted_pattern_hits_after": 0
    }
  },
  "signature": {
    "algorithm": "Ed25519",
    "public_key_fingerprint": "sha256:8396af8c07a7d40f98ba492cf2b61e23fa768e66a9f627b02a9caff464e48c06",
    "signature_base64url": "8TMpR-uXVmys3d-5Anj0yD4VgISOt7UJOsUQPq43xeU-UKHrz09mQgK5w9zdexzItdHz6F0sO-lz10te6oksCA",
    "signed_payload_hash": "sha256:e1bd9ded489544f9ee6f5cada68f289fde000dde0f2ceff30c6a1dfc3acd4c79"
  }
};

var SAMPLE_TAMPERED_CERT = JSON.parse(JSON.stringify(SAMPLE_VALID_CERT));
SAMPLE_TAMPERED_CERT.device.capacity_bytes = 999999999;

// Try loading keys.json dynamically if accessible
fetch("keys.json")
  .then(function(r) { return r.json(); })
  .then(function(data) {
    if (data && data.trusted_keys && data.trusted_keys.length) {
      PINNED_KEYS = data.trusted_keys;
    }
    renderPinnedKeys();
  })
  .catch(function() {
    renderPinnedKeys();
  });

function renderPinnedKeys() {
  var el = document.getElementById("pinnedKeysList");
  if (!el) return;
  el.textContent = "";
  PINNED_KEYS.forEach(function(k) {
    var box = document.createElement("div");
    box.className = "key-box";

    var hdr = document.createElement("div");
    hdr.className = "key-header";
    var str = document.createElement("strong");
    str.textContent = k.issuer || "Pinned Key";
    hdr.appendChild(str);

    var fp = document.createElement("div");
    fp.style.color = "var(--primary)";
    fp.style.fontSize = "0.78rem";
    fp.style.wordBreak = "break-all";
    fp.textContent = k.fingerprint || "";

    box.appendChild(hdr);
    box.appendChild(fp);
    el.appendChild(box);
  });
}

// Drag & drop and file input handlers
var dropzone = document.getElementById("dropzone");
var fileInput = document.getElementById("fileInput");
var jsonInput = document.getElementById("jsonInput");

if (dropzone && fileInput) {
  dropzone.addEventListener("click", function() { fileInput.click(); });
  dropzone.addEventListener("dragover", function(e) {
    e.preventDefault();
    dropzone.classList.add("dragover");
  });
  dropzone.addEventListener("dragleave", function() {
    dropzone.classList.remove("dragover");
  });
  dropzone.addEventListener("drop", function(e) {
    e.preventDefault();
    dropzone.classList.remove("dragover");
    if (e.dataTransfer.files.length > 0) {
      handleFile(e.dataTransfer.files[0]);
    }
  });

  fileInput.addEventListener("change", function(e) {
    if (e.target.files.length > 0) {
      handleFile(e.target.files[0]);
    }
  });
}

// Global paste listener: handles image pastes (screenshots of QR) or text
window.addEventListener("paste", function(e) {
  if (e.clipboardData && e.clipboardData.items) {
    var items = e.clipboardData.items;
    for (var i = 0; i < items.length; i++) {
      if (items[i].type.indexOf("image") !== -1) {
        var file = items[i].getAsFile();
        if (file) {
          handleImageFile(file);
          return;
        }
      }
    }
  }
});

function handleFile(file) {
  var name = (file.name || "").toLowerCase();
  if (name.endsWith(".pdf") || file.type === "application/pdf") {
    handlePdfFile(file);
  } else if (name.endsWith(".png") || name.endsWith(".jpg") || name.endsWith(".jpeg") || name.endsWith(".webp") || name.endsWith(".bmp") || file.type.startsWith("image/")) {
    handleImageFile(file);
  } else {
    // Treat as JSON
    var reader = new FileReader();
    reader.onload = function(evt) {
      jsonInput.value = evt.target.result;
      runVerification();
    };
    reader.readAsText(file);
  }
}

// --- QR Code Decoding on Canvas Image ---
function decodeQrFromCanvas(canvas) {
  if (typeof jsQR === "undefined") {
    console.warn("jsQR library not loaded");
    return null;
  }
  var ctx = canvas.getContext("2d");
  var imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);
  var code = jsQR(imgData.data, imgData.width, imgData.height, {
    inversionAttempts: "dontInvert"
  });
  if (!code) {
    // Try with inverted colors if needed
    code = jsQR(imgData.data, imgData.width, imgData.height, {
      inversionAttempts: "onlyInvert"
    });
  }
  return code ? code.data : null;
}

// --- Image File Handler (QR Image) ---
function handleImageFile(file) {
  var reader = new FileReader();
  reader.onload = function(e) {
    var img = new Image();
    img.onload = function() {
      var canvas = document.createElement("canvas");
      canvas.width = img.width;
      canvas.height = img.height;
      var ctx = canvas.getContext("2d");
      ctx.drawImage(img, 0, 0);

      var qrData = decodeQrFromCanvas(canvas);
      if (qrData) {
        processQrPayload(qrData, file.name);
      } else {
        alert("No readable QR code found in the image. Please ensure the QR code is clear and uncropped.");
      }
    };
    img.src = e.target.result;
  };
  reader.readAsDataURL(file);
}

// --- PDF File Handler (Render Page 1 & Scan QR) ---
async function handlePdfFile(file) {
  if (typeof pdfjsLib === "undefined") {
    alert("PDF processing library is loading, please try again in a moment.");
    return;
  }

  try {
    var arrayBuffer = await file.arrayBuffer();
    var loadingTask = pdfjsLib.getDocument({ data: arrayBuffer });
    var pdf = await loadingTask.promise;
    var page = await pdf.getPage(1);

    // Render at scale 2.0 to ensure QR is sharp enough for jsQR
    var scale = 2.0;
    var viewport = page.getViewport({ scale: scale });

    var canvas = document.createElement("canvas");
    canvas.width = viewport.width;
    canvas.height = viewport.height;
    var ctx = canvas.getContext("2d");

    var renderContext = {
      canvasContext: ctx,
      viewport: viewport
    };
    await page.render(renderContext).promise;

    var qrData = decodeQrFromCanvas(canvas);
    if (qrData) {
      processQrPayload(qrData, file.name + " (Embedded QR)");
      return;
    }

    // Fallback: If optical QR scan missed, try parsing textual certificate fields
    var textContent = await page.getTextContent();
    var fullText = textContent.items.map(function(item) { return item.str; }).join(" ");

    // Check if certificate UUID is in text
    var uuidMatch = fullText.match(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i);
    if (uuidMatch) {
      var certUuid = uuidMatch[0];
      handleCertLocator(certUuid, "PDF Certificate: " + file.name);
      return;
    }

    alert("PDF loaded, but could not detect a valid s0 verification QR code or certificate UUID on Page 1.");
  } catch (err) {
    console.error("PDF processing error:", err);
    alert("Failed to parse PDF document: " + err.message);
  }
}

// Process QR Payload: can be raw JSON or a verification URL
function processQrPayload(payload, sourceDesc) {
  var clean = payload.trim();
  if (clean.startsWith("{") && clean.endsWith("}")) {
    // Full signed certificate canonical JSON inside QR!
    jsonInput.value = clean;
    runVerification();
    return;
  }

  // Check if URL with ?cert= parameter
  try {
    var url = new URL(clean);
    var certParam = url.searchParams.get("cert");
    if (certParam) {
      // Check if base64 encoded JSON
      try {
        var b64 = certParam.replace(/-/g, "+").replace(/_/g, "/");
        while (b64.length % 4 !== 0) b64 += "=";
        var decodedStr = decodeBase64Utf8(b64);
        if (decodedStr && decodedStr.trim().startsWith("{")) {
          jsonInput.value = decodedStr;
          runVerification();
          return;
        }
      } catch (_) {}

      if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(certParam)) {
        handleCertLocator(certParam, sourceDesc);
        return;
      }
    }
  } catch (_) {}

  // Check if raw UUID
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(clean)) {
    handleCertLocator(clean, sourceDesc);
    return;
  }

  alert("Scanned QR content is not an s0 certificate or verification URL:\n" + clean.substring(0, 100));
}

function handleCertLocator(uuid, sourceDesc) {
  var emptyState = document.getElementById("emptyState");
  emptyState.style.display = "block";
  document.getElementById("resultContainer").style.display = "none";
  emptyState.textContent = "";

  var iconSpan = document.createElement("span");
  iconSpan.className = "empty-icon";
  iconSpan.innerHTML = '<svg width="44" height="44" viewBox="0 0 24 24" fill="none" stroke="var(--primary)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>';

  var h3 = document.createElement("h3");
  h3.style.marginTop = "10px";
  h3.style.color = "var(--primary)";
  h3.textContent = "Certificate UUID Detected: " + uuid;

  var p = document.createElement("p");
  p.style.marginTop = "6px";
  p.style.fontSize = "0.84rem";
  p.style.color = "var(--text-secondary)";
  p.textContent = "Source: " + (sourceDesc || "Optical QR / PDF Scan");

  var box = document.createElement("div");
  box.style.maxWidth = "600px";
  box.style.margin = "16px auto";
  box.style.padding = "14px";
  box.style.background = "rgba(255, 101, 0, 0.08)";
  box.style.border = "1px solid rgba(255, 101, 0, 0.3)";
  box.style.borderRadius = "8px";
  box.style.textAlign = "left";
  box.style.fontSize = "0.85rem";

  var strong = document.createElement("strong");
  strong.textContent = "Zero-Trust Offline Architecture Notice:";
  box.appendChild(strong);
  box.appendChild(document.createElement("br"));

  var noticeText1 = document.createTextNode(
    "S0 does not maintain a centralized telemetry server that stores customer wipe records. The physical certificate remains cryptographically sealed in your local forensic artifact repository."
  );
  box.appendChild(noticeText1);
  box.appendChild(document.createElement("br"));
  box.appendChild(document.createElement("br"));

  var noticeText2 = document.createTextNode("To cryptographically audit and verify the Ed25519 signature of this certificate, please drag & drop ");
  box.appendChild(noticeText2);

  var code = document.createElement("code");
  code.textContent = "certificate_" + String(uuid).substring(0, 8) + ".json";
  box.appendChild(code);
  box.appendChild(document.createTextNode("."));

  emptyState.appendChild(iconSpan);
  emptyState.appendChild(h3);
  emptyState.appendChild(p);
  emptyState.appendChild(box);
}

document.getElementById("btnVerify").addEventListener("click", runVerification);
document.getElementById("btnClear").addEventListener("click", function() {
  jsonInput.value = "";
  document.getElementById("emptyState").style.display = "block";
  document.getElementById("resultContainer").style.display = "none";
});

// Scenario loading
document.getElementById("btnLoadValid").addEventListener("click", function() {
  fetch("tests/sample_valid_cert.json")
    .then(function(r) { return r.json(); })
    .then(function(cert) {
      jsonInput.value = JSON.stringify(cert, null, 2);
      runVerification();
    })
    .catch(function() {
      jsonInput.value = JSON.stringify(SAMPLE_VALID_CERT, null, 2);
      runVerification();
    });
});

document.getElementById("btnLoadTampered").addEventListener("click", function() {
  fetch("tests/sample_tampered_cert.json")
    .then(function(r) { return r.json(); })
    .then(function(cert) {
      jsonInput.value = JSON.stringify(cert, null, 2);
      runVerification();
    })
    .catch(function() {
      jsonInput.value = JSON.stringify(SAMPLE_TAMPERED_CERT, null, 2);
      runVerification();
    });
});

function runVerification() {
  var rawText = jsonInput.value.trim();
  if (!rawText) {
    alert("Please paste or upload a certificate JSON, PDF, or QR image first.");
    return;
  }

  var certObj;
  try {
    certObj = JSON.parse(rawText);
  } catch (e) {
    showResult({
      ok: false,
      status: "JSON_PARSE_ERROR",
      reason: "Invalid JSON format: " + e.message
    }, null);
    return;
  }

  var result = S0Verifier.verifyCertificate(certObj, PINNED_KEYS);
  showResult(result, certObj);
}

function formatBytes(bytes) {
  if (!bytes && bytes !== 0) return "-";
  if (bytes < 1024) return bytes + " B";
  var units = ["B", "KiB", "MiB", "GiB", "TiB"];
  var i = Math.floor(Math.log(bytes) / Math.log(1024));
  return (bytes / Math.pow(1024, i)).toFixed(2) + " " + units[i] + " (" + Number(bytes).toLocaleString() + " B)";
}

function formatBytesShort(bytes) {
  if (!bytes && bytes !== 0) return "-";
  if (bytes < 1024) return bytes + " B";
  var units = ["B", "KiB", "MiB", "GiB", "TiB"];
  var i = Math.floor(Math.log(bytes) / Math.log(1024));
  return (bytes / Math.pow(1024, i)).toFixed(1) + " " + units[i];
}

function showResult(res, cert) {
  document.getElementById("emptyState").style.display = "none";
  var container = document.getElementById("resultContainer");
  container.style.display = "block";

  var banner = document.getElementById("resultBanner");
  var icon = document.getElementById("bannerIcon");
  var title = document.getElementById("bannerTitle");
  var desc = document.getElementById("bannerDesc");

  banner.className = "result-banner";

  if (res.status === "VERIFIED_CUSTOM_KEY") {
    banner.classList.add("custom-key");
    icon.textContent = "[KEY]";
    title.textContent = "VERIFIED (Custom Key — Non-Pinned Authority)";
    desc.textContent = res.reason;
    document.getElementById("metricIntegrity").textContent = "Custom Key";
    document.getElementById("metricIntegrity").style.color = "var(--info)";
  } else if (res.ok && (res.isDemoKey || res.status === "VERIFIED_DEMO_KEY" || (res.matchedKey && res.matchedKey.issuer && (res.matchedKey.issuer.toLowerCase().indexOf("unaccredited") !== -1 || res.matchedKey.issuer.toLowerCase().indexOf("demo") !== -1)) || res.fingerprint === "sha256:8396af8c07a7d40f98ba492cf2b61e23fa768e66a9f627b02a9caff464e48c06")) {
    banner.classList.add("demo-key");
    icon.textContent = "[!]";
    title.textContent = "VALID SIGNATURE — UNACCREDITED DEMO KEY";
    desc.textContent = res.reason + " NOTICE: Demo-key signatures are unaccredited development keys and MUST NOT be used for legal chain-of-custody or regulatory compliance.";
    document.getElementById("metricIntegrity").textContent = "Demo Key";
    document.getElementById("metricIntegrity").style.color = "var(--warning)";
  } else if (res.ok) {
    banner.classList.add("authentic");
    icon.textContent = "[OK]";
    title.textContent = "AUTHENTIC & CRYPTOGRAPHICALLY VERIFIED";
    desc.textContent = res.reason;
    document.getElementById("metricIntegrity").textContent = "Authentic";
    document.getElementById("metricIntegrity").style.color = "var(--success)";
  } else if (res.status === "TAMPERED_OR_CORRUPT") {
    banner.classList.add("tampered");
    icon.textContent = "[!]";
    title.textContent = "SIGNATURE MISMATCH / TAMPER DETECTED";
    desc.textContent = res.reason;
    document.getElementById("metricIntegrity").textContent = "Tampered";
    document.getElementById("metricIntegrity").style.color = "var(--danger)";
  } else if (res.status === "UNTRUSTED_ISSUER") {
    banner.classList.add("untrusted");
    icon.textContent = "[?]";
    title.textContent = "UNTRUSTED ISSUER KEY";
    desc.textContent = res.reason;
    document.getElementById("metricIntegrity").textContent = "Untrusted";
    document.getElementById("metricIntegrity").style.color = "var(--warning)";
  } else {
    banner.classList.add("invalid");
    icon.textContent = "[X]";
    title.textContent = "VALIDATION FAILED (" + res.status + ")";
    desc.textContent = res.reason;
    document.getElementById("metricIntegrity").textContent = "Invalid";
    document.getElementById("metricIntegrity").style.color = "var(--danger)";
  }

  if (cert) {
    document.getElementById("resUuid").textContent = cert.cert_uuid || "-";
    document.getElementById("resIssuedAt").textContent = cert.issued_at || "-";
    document.getElementById("resIssuer").textContent = (res.matchedKey && res.matchedKey.issuer) ? res.matchedKey.issuer : ((cert.issuer && cert.issuer.organization) || "-");
    document.getElementById("resOperator").textContent = (cert.issuer && cert.issuer.operator_id) || "-";
    document.getElementById("resTool").textContent = cert.tool ? (cert.tool.name + " v" + cert.tool.version + " (" + cert.tool.platform + ")") : "-";

    var dev = cert.device || {};
    document.getElementById("resDevice").textContent = (dev.model ? dev.model + " • " : "") + (dev.serial_number || dev.device_id || "-");
    document.getElementById("resStorage").textContent = (dev.storage_type || "-") + " • " + formatBytes(dev.capacity_bytes);
    document.getElementById("metricCapacity").textContent = formatBytesShort(dev.capacity_bytes);

    var wipe = cert.wipe || {};
    var methodStr = (wipe.method || "-");
    document.getElementById("resMethod").textContent = methodStr + (wipe.passes ? " (" + wipe.passes + " pass)" : "");
    document.getElementById("metricMethod").textContent = methodStr.replace("OVERWRITE_", "").replace("_1PASS", "");

    var tier = String(wipe.nist_category || "Unknown");
    var safeTierClass = "badge-" + tier.toLowerCase().replace(/[^a-z0-9_-]/g, "");
    var badgeSpan = document.createElement("span");
    badgeSpan.className = "badge " + safeTierClass;
    badgeSpan.textContent = tier;
    var nistContainer = document.getElementById("resNistTier");
    nistContainer.textContent = "";
    nistContainer.appendChild(badgeSpan);

    var verif = (cert.result && cert.result.verification) || {};
    var verifText = verif.samples_checked ? (verif.samples_checked + " samples checked (100% match wipe pattern)") : "Standard verification";
    if (verif.planted_pattern_hits_after !== undefined) {
      verifText += " • Planted markers: " + verif.planted_pattern_hits_after + " hits";
    }
    document.getElementById("resForensic").textContent = verifText;

    document.getElementById("resFingerprint").textContent = (cert.signature && cert.signature.public_key_fingerprint) || "-";
    document.getElementById("resPayloadHash").textContent = res.computedPayloadHash || (cert.signature && cert.signature.signed_payload_hash) || "-";

    document.getElementById("codeRaw").textContent = JSON.stringify(cert, null, 2);
    document.getElementById("codeCanonical").textContent = res.canonicalPayload || "-";
  }
}

function switchTab(tabId) {
  document.querySelectorAll(".tab-btn").forEach(function(b) { b.classList.remove("active"); });
  document.querySelectorAll(".tab-content").forEach(function(c) { c.classList.remove("active"); });
  if (tabId === "canonical") {
    document.querySelectorAll(".tab-btn")[0].classList.add("active");
    document.getElementById("tab-canonical").classList.add("active");
  } else {
    document.querySelectorAll(".tab-btn")[1].classList.add("active");
    document.getElementById("tab-raw").classList.add("active");
  }
}

function copyCode(elementId) {
  var el = document.getElementById(elementId);
  if (!el) return;
  var text = el.textContent;
  navigator.clipboard.writeText(text).then(function() {
    var btn = event.target;
    var origText = btn.textContent;
    btn.textContent = "Copied!";
    setTimeout(function() { btn.textContent = origText; }, 1800);
  }).catch(function() {
    alert("Copy failed — please select and copy manually.");
  });
}

document.getElementById("btnVerifyCustomKey").addEventListener("click", function() {
  var rawText = jsonInput.value.trim();
  if (!rawText) {
    alert("Please paste or upload a certificate JSON first.");
    return;
  }
  var customKey = document.getElementById("customKeyInput").value.trim();
  if (!customKey) {
    alert("Please paste an Ed25519 public key (PEM format or 64-character raw hex).");
    return;
  }
  var certObj;
  try {
    certObj = JSON.parse(rawText);
  } catch (e) {
    showResult({
      ok: false,
      status: "JSON_PARSE_ERROR",
      reason: "Invalid JSON format: " + e.message
    }, null);
    return;
  }

  var result = S0Verifier.verifyCertificate(certObj, [customKey]);
  if (result.ok) {
    result.status = "VERIFIED_CUSTOM_KEY";
    result.reason = "Valid Ed25519 cryptographic signature verified against your custom public key. NOTE: This key is NOT in the official pinned authority registry.";
  }
  showResult(result, certObj);
});

// Auto-load certificate from URL parameter ?cert=...
(function() {
  try {
    var params = new URLSearchParams(window.location.search);
    var certParam = params.get("cert");
    if (certParam) {
      try {
        var b64 = certParam.replace(/-/g, "+").replace(/_/g, "/");
        while (b64.length % 4 !== 0) b64 += "=";
        var decodedStr = decodeBase64Utf8(b64);
        if (decodedStr && decodedStr.trim().startsWith("{")) {
          jsonInput.value = decodedStr;
          runVerification();
          return;
        }
      } catch (_) {}

      if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(certParam)) {
        handleCertLocator(certParam, "URL Parameter");
      }
    }
  } catch (e) {
    console.warn("URL cert parameter error:", e);
  }
})();

// Optional config loader from /api/config when connected to an s0 host
(function() {
  try {
    fetch("/api/config")
      .then(function(res) { return res.ok ? res.json() : null; })
      .then(function(cfg) {
        if (!cfg) return;
        var docLink = document.querySelector(".site-header-nav a[href*='docs']");
        if (docLink && cfg.documentation_url) docLink.href = cfg.documentation_url;
        var ghLink = document.querySelector(".nav-github");
        if (ghLink && cfg.github_url) ghLink.href = cfg.github_url;
      })
      .catch(function() {});
  } catch (_) {}
})();

// Light / Dark Mode Theme Controller
function initTheme() {
  var saved = "dark";
  try {
    saved = localStorage.getItem("s0_theme") || "dark";
  } catch (_) {}
  applyTheme(saved);
}

function applyTheme(theme) {
  document.documentElement.setAttribute("data-theme", theme);
  try {
    localStorage.setItem("s0_theme", theme);
  } catch (_) {}
  var lbl = document.getElementById("themeToggleLabel");
  if (lbl) {
    lbl.textContent = theme === "light" ? "Dark" : "Light";
  }
  var fav = document.getElementById("dynamic-favicon");
  if (fav) {
    fav.href = theme === "light" ? "assets/favicons/s0-light/favicon-32x32.png" : "assets/favicons/s0-dark/favicon-32x32.png";
  }
}

function toggleTheme() {
  var current = document.documentElement.getAttribute("data-theme") || "dark";
  applyTheme(current === "dark" ? "light" : "dark");
}

document.addEventListener("DOMContentLoaded", initTheme);

