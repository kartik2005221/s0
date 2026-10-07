/**
 * s0 Verifier — Pure Client-Side Controller
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

if (window.S0_TRUSTED_KEYS && window.S0_TRUSTED_KEYS.length) {
  PINNED_KEYS = window.S0_TRUSTED_KEYS;
}

// Try loading keys.json dynamically if accessible over HTTP
if (window.location && window.location.protocol !== "file:") {
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
} else {
  renderPinnedKeys();
}

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
    reader.onerror = function() {
      setPdfStatus("Could not read " + (file.name || "the selected file") + ".", true);
    };
    reader.readAsText(file);
  }
}

// --- QR Code Decoding on Canvas Image ---
//
// jsQR is a third-party decoder we do not control. Some builds (including the one
// vendored here) throw a TypeError from inside locate() for certain
// `inversionAttempts` values, so every invocation is isolated: a decoder fault is
// reported as "no code found", never propagated to the caller. "attemptBoth"
// covers the dontInvert case internally, which is why the previously used
// single-mode inversion retry (and its guaranteed crash) is no longer needed.
var QR_DECODE_INVERSION_MODE = "attemptBoth";

function jsQRSafe(imgData) {
  if (typeof jsQR !== "function") {
    console.warn("jsQR library not loaded");
    return null;
  }
  try {
    var code = jsQR(imgData.data, imgData.width, imgData.height, {
      inversionAttempts: QR_DECODE_INVERSION_MODE
    });
    return code && code.data ? code.data : null;
  } catch (err) {
    console.warn("QR decode attempt failed:", err && err.message);
    return null;
  }
}

function decodeQrFromCanvas(canvas) {
  var ctx = canvas.getContext("2d", { willReadFrequently: true });
  var imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);
  return jsQRSafe(imgData);
}

// Render one PDF page onto an opaque white canvas. pdf.js leaves untouched regions
// transparent, and a transparent (alpha=0) pixel confuses QR binarisers.
async function renderPdfPageToCanvas(page, scale) {
  var viewport = page.getViewport({ scale: scale });
  if (!viewport || !viewport.width || !viewport.height) {
    throw new Error("pdf.js returned an unusable viewport for this page");
  }
  var canvas = document.createElement("canvas");
  canvas.width = Math.max(1, Math.floor(viewport.width));
  canvas.height = Math.max(1, Math.floor(viewport.height));
  var ctx = canvas.getContext("2d", { willReadFrequently: true });
  ctx.fillStyle = "#ffffff";
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  await page.render({ canvasContext: ctx, viewport: viewport }).promise;
  return canvas;
}

// --- Image File Handler (QR Image) ---
function handleImageFile(file) {
  setPdfStatus("Reading image…", false);
  var reader = new FileReader();
  reader.onload = function(e) {
    var img = new Image();
    img.onload = function() {
      var canvas = document.createElement("canvas");
      canvas.width = img.naturalWidth || img.width;
      canvas.height = img.naturalHeight || img.height;
      var ctx = canvas.getContext("2d", { willReadFrequently: true });
      ctx.fillStyle = "#ffffff";
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.drawImage(img, 0, 0);

      var qrData = decodeQrFromCanvas(canvas);
      if (qrData) {
        setPdfStatus("", false);
        processQrPayload(qrData, file.name);
      } else {
        setPdfStatus(
          "No readable QR code was found in " + (file.name || "the image") +
          ". Screenshots work best when the QR is square, uncropped and fully visible.",
          true
        );
      }
    };
    img.onerror = function() {
      setPdfStatus((file.name || "The image") + " could not be decoded. Try exporting it as PNG.", true);
    };
    img.src = e.target.result;
  };
  reader.onerror = function() {
    setPdfStatus("Could not read " + (file.name || "the image") + ".", true);
  };
  reader.readAsDataURL(file);
}

// --- PDF File Handler ---
//
// s0 PDF certificates are rendered from a flowable layout, so the QR block lands on
// page 2 whenever the device/wipe/signature tables overflow the first page. Scanning
// only page 1 is why s0 certificates used to fail here. We therefore walk every page
// in ascending order, attempt an optical QR decode at a small ladder of scales, and
// independently fall back to the PDF text layer — which always carries the
// certificate UUID. Every stage is failure-isolated so that one bad page, one missing
// glyph or one decoder fault cannot abort verification.
var PDF_QR_SCALE_LADDER = [2, 3, 4];
var PDF_MAX_QR_PAGES = 24;
var UUID_RE = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i;

function setPdfStatus(message, isError) {
  var el = document.getElementById("fileStatus");
  if (!el) return;
  el.textContent = message;
  el.style.display = message ? "block" : "none";
  el.style.color = isError ? "var(--danger)" : "var(--text-secondary)";
}

async function handlePdfFile(file) {
  if (typeof pdfjsLib === "undefined") {
    alert("PDF processing library is loading, please try again in a moment.");
    return;
  }

  setPdfStatus("Reading PDF…", false);

  var doc = null;
  try {
    var arrayBuffer = await file.arrayBuffer();
    var loadingTask = pdfjsLib.getDocument({
      data: arrayBuffer,
      cMapUrl: "vendor/",
      cMapPacked: true,
      // The vendored pdf.js is 3.11.174, which is inside the range affected by
      // CVE-2024-4367: a crafted font can achieve arbitrary JavaScript execution
      // through the font evaluator, which reaches eval. Upgrading is the real fix
      // and is blocked on re-vendoring; this flag removes the eval path the
      // advisory depends on, so a malicious font cannot execute even on this
      // version. A font that needs the evaluator now fails to render instead of
      // running, which is the correct trade for a certificate viewer.
      //
      // This matters more than usual here: /portal is served from the same origin
      // as the dashboard's destructive API, so script execution in the PDF viewer
      // is script execution with access to /api/erase-files.
      isEvalSupported: false
    });
    doc = await loadingTask.promise;
  } catch (err) {
    console.error("PDF load error:", err);
    setPdfStatus("This file could not be opened as a PDF (" + (err && err.message) + ").", true);
    alert("Failed to open PDF document: " + (err && err.message ? err.message : "unknown error"));
    return;
  }

  var pageCount = doc.numPages || 0;
  var pagesToScan = Math.min(pageCount, PDF_MAX_QR_PAGES);
  var qrData = null;
  var qrSource = null;
  var textLayers = [];
  var decodeFaults = [];

  for (var pno = 1; pno <= pagesToScan && !qrData; pno++) {
    var page = null;
    try {
      page = await doc.getPage(pno);
    } catch (err) {
      decodeFaults.push("page " + pno + " unreadable");
      continue;
    }

    // Text layer first: cheap, deterministic, and independent of the rasteriser.
    try {
      var textContent = await page.getTextContent();
      if (textContent && textContent.items && textContent.items.length) {
        textLayers.push(textContent.items.map(function (item) { return item.str; }).join(" "));
      }
    } catch (err) {
      decodeFaults.push("page " + pno + " text layer unavailable");
    }

    for (var s = 0; s < PDF_QR_SCALE_LADDER.length && !qrData; s++) {
      try {
        var canvas = await renderPdfPageToCanvas(page, PDF_QR_SCALE_LADDER[s]);
        var decoded = decodeQrFromCanvas(canvas);
        if (decoded) {
          qrData = decoded;
          qrSource = file.name + " (page " + pno + ")";
        }
        // Release the backing store promptly; large pages are memory-hungry.
        canvas.width = 1;
        canvas.height = 1;
      } catch (err) {
        decodeFaults.push("page " + pno + " render failed at scale " + PDF_QR_SCALE_LADDER[s]);
      }
    }
    page.cleanup && page.cleanup();
  }

  if (qrData) {
    processQrPayload(qrData, qrSource);
    if (doc.cleanup) doc.cleanup();
    return;
  }

  // Optical decode failed — recover the certificate identity from the text layer
  // across every scanned page instead of failing outright.
  var fullText = textLayers.join(" ");
  var uuidMatch = fullText.match(UUID_RE);
  if (uuidMatch) {
    handleCertLocator(uuidMatch[0], "PDF Certificate: " + file.name);
    if (doc.cleanup) doc.cleanup();
    return;
  }

  var hint = "";
  if (decodeFaults.length) {
    hint = " (" + decodeFaults.length + " decode step(s) degraded: " + decodeFaults[0] + ")";
  }
  if (pageCount > PDF_MAX_QR_PAGES) {
    hint += " Only the first " + PDF_MAX_QR_PAGES + " of " + pageCount + " pages were scanned.";
  }
  setPdfStatus(
    "No s0 verification QR code or certificate UUID was found in this PDF" + hint +
    ". If this is an s0 certificate, drag & drop the matching certificate JSON to verify the signature.",
    true
  );
  if (doc.cleanup) doc.cleanup();
}

// Process QR Payload: can be raw JSON or a verification URL
function processQrPayload(payload, sourceDesc) {
  var clean = (payload || "").trim();
  if (clean.startsWith("{") && clean.endsWith("}")) {
    // Full signed certificate canonical JSON inside QR!
    setPdfStatus("", false);
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

  setPdfStatus("The QR code decoded, but its contents are not an s0 certificate or verification URL.", true);
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
  strong.textContent = "Offline Architecture Notice:";
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
  setPdfStatus("", false);
});

// Scenario loading
document.getElementById("btnLoadValid").addEventListener("click", function() {
  if (window.location && window.location.protocol !== "file:") {
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
  } else {
    jsonInput.value = JSON.stringify(SAMPLE_VALID_CERT, null, 2);
    runVerification();
  }
});

document.getElementById("btnLoadTampered").addEventListener("click", function() {
  if (window.location && window.location.protocol !== "file:") {
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
  } else {
    jsonInput.value = JSON.stringify(SAMPLE_TAMPERED_CERT, null, 2);
    runVerification();
  }
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

  var result = S0Verifier.verifyCertificate(certObj, PINNED_KEYS, { rawJson: rawText });
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
    var sampleCount = verif.samples_checked || 0;
    var sampleBytes = verif.sample_bytes_each || 0;
    var verifText = sampleCount
      ? (sampleCount + " read-back sample" + (sampleCount === 1 ? "" : "s") +
         (sampleBytes ? " × " + sampleBytes.toLocaleString() + " B" : "") +
         (verif.all_samples_match_wipe_pattern === false ? " — NOT all matched" : " — all match the wipe pattern"))
      : (verif.method ? verif.method.replace(/_/g, " ") : "No post-operation verification recorded");
    if (verif.planted_pattern_hits_after !== undefined) {
      verifText += " • Planted markers: " + verif.planted_pattern_hits_after + " hit(s)";
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
    fav.href = theme === "light" ? "../assets/favicons/s0-light/favicon-32x32.png" : "../assets/favicons/s0-dark/favicon-32x32.png";
  }
  var logo = document.getElementById("headerLogo");
  if (logo) {
    logo.src = theme === "light" ? "../assets/favicons/s0-light/favicon-32x32.png" : "../assets/favicons/s0-dark/favicon-32x32.png";
  }
  var footerLogo = document.getElementById("footerLogo");
  if (footerLogo) {
    footerLogo.src = theme === "light" ? "../assets/favicons/s0-light/favicon-32x32.png" : "../assets/favicons/s0-dark/favicon-32x32.png";
  }
}

function toggleTheme() {
  var current = document.documentElement.getAttribute("data-theme") || "dark";
  applyTheme(current === "dark" ? "light" : "dark");
}

function initScrollProgress() {
  var progressBar = document.getElementById("scrollProgress");
  if (!progressBar) return;

  window.addEventListener("scroll", function () {
    var winScroll = document.documentElement.scrollTop || document.body.scrollTop;
    var height = document.documentElement.scrollHeight - document.documentElement.clientHeight;
    var scrolled = height > 0 ? (winScroll / height) * 100 : 0;
    progressBar.style.width = scrolled + "%";
  }, { passive: true });
}

/* Interaction wiring.
 *
 * The theme toggle, the two result tabs and the two copy buttons used to carry
 * inline onclick attributes. This page's policy is script-src 'self' with no
 * 'unsafe-inline' -- inline handlers require 'unsafe-inline', so the browser
 * blocked all five. A verifier whose copy button silently does nothing is
 * worse than one without the button, so they are bound here instead.
 */
function wireInteractions() {
  document.addEventListener("click", function (event) {
    var btn = event.target.closest("button");
    if (!btn) return;

    if (btn.dataset.copyTarget) {
      copyCode(btn.dataset.copyTarget);
      return;
    }
    if (btn.dataset.tab) {
      switchTab(btn.dataset.tab);
      return;
    }
    if (btn.dataset.action === "toggle-theme") {
      toggleTheme();
    }
  });
}

document.addEventListener("DOMContentLoaded", initTheme);
document.addEventListener("DOMContentLoaded", initScrollProgress);
document.addEventListener("DOMContentLoaded", wireInteractions);

