/**
 * s0 Forensic & Sanitization Dashboard Controller
 */

let allBlocksCache = [];
let currentJobId = null;
let appConfig = null;

// Supported extensions catalog for Carver
const CARVER_SIGNATURES = [
  { ext: "jpg", cat: "Images", name: "JPEG Image" },
  { ext: "png", cat: "Images", name: "PNG Image" },
  { ext: "gif", cat: "Images", name: "GIF Image" },
  { ext: "bmp", cat: "Images", name: "BMP Image" },
  { ext: "pdf", cat: "Documents", name: "PDF Document" },
  { ext: "sqlite", cat: "Documents", name: "SQLite Database" },
  { ext: "pcap", cat: "Documents", name: "PCAP Capture" },
  { ext: "pcapng", cat: "Documents", name: "PCAP Next-Gen" },
  { ext: "zip", cat: "Archives", name: "ZIP / Office" },
  { ext: "gz", cat: "Archives", name: "GZIP Archive" },
  { ext: "7z", cat: "Archives", name: "7-Zip Archive" },
  { ext: "mp3", cat: "Audio", name: "MP3 Audio" },
  { ext: "wav", cat: "Audio", name: "WAV Audio" },
  { ext: "flac", cat: "Audio", name: "FLAC Lossless" },
  { ext: "ogg", cat: "Audio", name: "OGG Container" },
  { ext: "elf", cat: "Binaries", name: "ELF Executable" },
];

function escapeHtml(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// --- Navigation & URL Routing ---
function switchNav(tabId, el, updateHash = true) {
  const cleanId = tabId.replace(/^tab-/, "").replace(/^#/, "");
  document.querySelectorAll(".nav-tab").forEach(b => b.classList.remove("active"));
  document.querySelectorAll(".tab-content").forEach(p => p.classList.remove("active"));

  if (!el) {
    el = document.querySelector(`.nav-tab[data-tab="${cleanId}"]`) ||
         document.querySelector(`.nav-tab[onclick*="'${cleanId}'"]`);
  }
  if (el) el.classList.add("active");

  const target = document.getElementById("tab-" + cleanId);
  if (target) target.classList.add("active");

  if (updateHash && window.location.hash !== "#" + cleanId) {
    history.replaceState(null, "", "#" + cleanId);
  }

  if (cleanId === "audit") loadAuditBlocks();
}

function handleHashRouting() {
  const hash = window.location.hash.slice(1);
  if (hash && ["drive", "file", "carve", "image", "audit"].includes(hash)) {
    switchNav(hash, null, false);
  }
}

function clearLog(logId) {
  const el = document.getElementById(logId);
  if (el) el.textContent = "";
}

function setHeaderJobStatus(text, type) {
  const el = document.getElementById("headerJobStatus");
  if (!el) return;
  el.textContent = text;
  if (type === "running") {
    el.style.color = "var(--accent-cyan)";
  } else if (type === "success") {
    el.style.color = "var(--accent-emerald)";
  } else if (type === "error") {
    el.style.color = "var(--accent-crimson)";
  } else {
    el.style.color = "";
  }
}

// Helper: read a file as text
function readFileAsText(file) {
  return new Promise((resolve, reject) => {
    if (!file) return resolve(null);
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = reject;
    reader.readAsText(file);
  });
}

function getAuthToken() {
  const meta = document.querySelector('meta[name="s0-auth-token"]');
  if (meta && meta.content) {
    return meta.content;
  }
  return (window.appConfig && window.appConfig.auth_token) || "";
}

// --- Dynamic Config Loader ---
async function loadAppConfig() {
  try {
    const res = await fetch("/api/config");
    if (!res.ok) return;
    appConfig = await res.json();
    window.appConfig = appConfig;

    // Update header links
    const docLink = document.getElementById("navDocLink");
    if (docLink && appConfig.documentation_url) docLink.href = appConfig.documentation_url;

    const portalLink = document.getElementById("navPortalLink");
    if (portalLink && appConfig.verification_portal_url) portalLink.href = appConfig.verification_portal_url;

    const ghLink = document.getElementById("navGithubLink");
    if (ghLink && appConfig.github_url) ghLink.href = appConfig.github_url;

    // Prefill default operator & organization
    const opFields = ["driveOperator", "fileOperator", "carveOperator", "imageOperator"];
    opFields.forEach(id => {
      const el = document.getElementById(id);
      if (el && appConfig.default_operator) {
        if (!el.value || el.value === "op-forensic") {
          el.value = appConfig.default_operator;
        }
      }
    });

    const orgFields = ["driveOrganization", "fileOrganization", "carveOrganization", "imageOrganization"];
    orgFields.forEach(id => {
      const el = document.getElementById(id);
      if (el && appConfig.default_organization) {
        if (!el.value || el.value.includes("Digital Forensics")) {
          el.value = appConfig.default_organization;
        }
      }
    });
  } catch (e) {
    console.warn("Config fetch note:", e);
  }
}

// --- URL Parameter Pre-fill Engine ---
function readUrlParams() {
  const params = new URLSearchParams(window.location.search);

  // Tab
  const tabParam = params.get("tab");
  if (tabParam && ["drive", "file", "carve", "image", "audit"].includes(tabParam)) {
    switchNav(tabParam, null, true);
  }

  // Target
  const targetParam = params.get("target");
  if (targetParam) {
    const driveSel = document.getElementById("driveSelect");
    if (driveSel) driveSel.value = targetParam;
    const carveSel = document.getElementById("carveTargetSelect");
    if (carveSel) carveSel.value = targetParam;
  }

  // Pattern
  const patternParam = params.get("pattern");
  if (patternParam) {
    const drivePat = document.getElementById("drivePattern");
    if (drivePat) drivePat.value = patternParam;
    const filePat = document.getElementById("filePattern");
    if (filePat) filePat.value = patternParam;
  }

  // Operator
  const opParam = params.get("operator");
  if (opParam) {
    ["driveOperator", "fileOperator", "carveOperator", "imageOperator"].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.value = opParam;
    });
  }

  // Organization
  const orgParam = params.get("organization") || params.get("org");
  if (orgParam) {
    ["driveOrganization", "fileOrganization", "carveOrganization", "imageOrganization"].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.value = orgParam;
    });
  }

  // File targets
  const filesParam = params.get("files") || params.get("targets");
  if (filesParam) {
    const fArea = document.getElementById("fileTargets");
    if (fArea) fArea.value = filesParam.replace(/,/g, "\n");
  }

  // Output directory
  const outDirParam = params.get("out_dir");
  if (outDirParam) {
    ["driveOutDir", "fileOutDir", "carveOutDir", "imageOutDir"].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.value = outDirParam;
    });
  }

  // Key path
  const keyParam = params.get("key");
  if (keyParam) {
    ["driveKeyPath", "fileKeyPath", "carveKeyPath", "imageKeyPath"].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.value = keyParam;
    });
  }
}

// --- Devices & Plan Loading ---
async function loadDevices() {
  try {
    const res = await fetch("/api/devices");
    const data = await res.json();
    const driveSel = document.getElementById("driveSelect");
    const carveSel = document.getElementById("carveTargetSelect");
    const imageSel = document.getElementById("imageSourceSelect");
    driveSel.innerHTML = "";
    carveSel.innerHTML = "";
    if (imageSel) imageSel.innerHTML = "";

    const all = [...(data.block || []), ...(data.images || [])];
    if (all.length === 0) {
      const opt = document.createElement("option");
      opt.value = "";
      opt.textContent = "No storage devices or images found";
      driveSel.appendChild(opt);
      carveSel.appendChild(opt.cloneNode(true));
      if (imageSel) imageSel.appendChild(opt.cloneNode(true));
      return;
    }

    all.forEach(d => {
      const opt = document.createElement("option");
      opt.value = d.path;
      const mb = (d.capacity_bytes / (1024 * 1024)).toFixed(1);
      const modelStr = d.model ? ` • ${d.model}` : (d.storage_type ? ` [${d.storage_type}]` : "");
      opt.textContent = `${d.path} (${mb} MB)${modelStr}`;
      driveSel.appendChild(opt);
      carveSel.appendChild(opt.cloneNode(true));
      if (imageSel) imageSel.appendChild(opt.cloneNode(true));
    });

    onDriveSelected();
  } catch (e) {
    console.error("Failed to load devices", e);
  }
}

async function onDriveSelected() {
  const target = document.getElementById("driveSelect").value;
  const promptEl = document.getElementById("driveConfirmPromptPath");
  if (promptEl) promptEl.textContent = target || "target device path";
  if (!target) return;
  try {
    const res = await fetch("/api/plan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target })
    });
    if (!res.ok) return;
    const plan = await res.json();

    const mb = (plan.target.capacity_bytes / (1024 * 1024)).toFixed(1);
    document.getElementById("driveCapVal").textContent = `${mb} MB (${plan.target.storage_type || "UNKNOWN"})`;
    document.getElementById("driveMethodVal").textContent = plan.method_id || "None";
    if (plan.hpa_dco) {
      document.getElementById("driveHpaVal").innerHTML = `<span class="badge badge-amber">${plan.hpa_dco.status || "Check required"}</span>`;
    } else {
      document.getElementById("driveHpaVal").textContent = "Normal (No HPA/DCO detected)";
    }
  } catch (e) {
    console.warn("Plan query note:", e);
  }
}

// --- Module 1: Drive Sanitizer ---
async function startDriveWipe() {
  const target = document.getElementById("driveSelect").value;
  const confirm_text = document.getElementById("driveConfirm").value.trim();

  // Pattern standard selection: values are composite e.g. "zero_1", "random_3", "random_7"
  const patternSelectVal = document.getElementById("drivePattern").value;
  let pattern = "zero";
  let passes = 1;
  if (patternSelectVal.includes("_")) {
    const parts = patternSelectVal.split("_");
    pattern = parts[0];
    passes = parseInt(parts[1], 10) || 1;
  } else {
    pattern = patternSelectVal;
  }

  const operator = document.getElementById("driveOperator").value.trim() || "op-forensic";
  const organization = document.getElementById("driveOrganization").value.trim() || "Digital Forensics & Data Sanitization Lab";

  // Advanced options
  const key_path = (document.getElementById("driveKeyPath")?.value || "").trim() || null;
  const key_file_el = document.getElementById("driveKeyUpload");
  let key_data = null;
  if (key_file_el && key_file_el.files && key_file_el.files.length > 0) {
    key_data = await readFileAsText(key_file_el.files[0]);
  }

  const out_dir = (document.getElementById("driveOutDir")?.value || "").trim() || null;
  const verify_samples = parseInt(document.getElementById("driveVerifySamples")?.value, 10) || 64;
  const no_pdf = !(document.getElementById("drivePdfToggle")?.checked ?? true);
  const portal_url = (document.getElementById("drivePortalUrl")?.value || "").trim() || null;

  if (confirm_text !== target) {
    alert(`Destructive safety lock: Please type the exact target path "${target}" in the confirmation box.`);
    return;
  }

  document.getElementById("driveResultCard").classList.remove("active");
  const driveBadge = document.getElementById("driveStatusBadge");
  if (driveBadge) {
    driveBadge.className = "badge badge-cyan";
    driveBadge.textContent = "STATUS: RUNNING";
  }
  setHeaderJobStatus("RUNNING", "running");

  try {
    const res = await fetch("/api/wipe", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-S0-Auth-Token": getAuthToken(),
      },
      body: JSON.stringify({
        target,
        confirm_text,
        pattern,
        passes,
        operator,
        organization,
        key_path,
        key_data,
        out_dir,
        no_pdf,
        verify_samples,
        portal_url,
      })
    });
    const data = await res.json();
    if (data.job_id) {
      trackJob(data.job_id, "driveStatusBadge", "driveLog", onDriveWipeDone);
    } else {
      alert(data.detail || "Error starting wipe");
      if (driveBadge) {
        driveBadge.className = "badge badge-red";
        driveBadge.textContent = "STATUS: ERROR";
      }
      setHeaderJobStatus("ERROR", "error");
    }
  } catch (err) {
    alert("Failed to communicate with wipe engine: " + err);
    setHeaderJobStatus("ERROR", "error");
  }
}

function renderDemoKeyNotice(container, isDemo) {
  if (!isDemo || !container) return;
  const alert = document.createElement("div");
  alert.style.cssText = "width: 100%; margin-top: 10px; padding: 8px 12px; background: rgba(245, 158, 11, 0.12); border: 1px solid rgba(245, 158, 11, 0.4); border-radius: 6px; color: var(--warning); font-size: 0.8rem; font-family: var(--font-sans); display: flex; align-items: center; gap: 8px;";
  const icon = document.createElement("span");
  icon.textContent = "⚠️";
  const text = document.createElement("span");
  const strong = document.createElement("strong");
  strong.textContent = "Notice: ";
  text.appendChild(strong);
  text.appendChild(document.createTextNode("Certificate signed with unaccredited public demonstration key. Do not use for legal chain-of-custody."));
  alert.appendChild(icon);
  alert.appendChild(text);
  container.appendChild(alert);
}

function onDriveWipeDone(job) {
  const resCard = document.getElementById("driveResultCard");
  const actionBox = document.getElementById("driveActionButtons");
  resCard.classList.add("active");
  actionBox.innerHTML = "";

  if (job.result && job.result.cert_filename) {
    const btnJson = document.createElement("a");
    btnJson.className = "btn btn-secondary btn-sm";
    btnJson.href = `/api/download/${job.id}/${job.result.cert_filename}`;
    btnJson.textContent = "Download JSON Certificate";
    actionBox.appendChild(btnJson);
  }
  if (job.result && job.result.pdf_filename) {
    const btnPdf = document.createElement("a");
    btnPdf.className = "btn btn-primary btn-sm";
    btnPdf.href = `/api/download/${job.id}/${job.result.pdf_filename}`;
    btnPdf.textContent = "Download PDF Certificate";
    actionBox.appendChild(btnPdf);
  }
  renderDemoKeyNotice(actionBox, job.demo_key_warning);
}

// --- Module 2: File & Folder Eraser ---
function addSampleFileTarget() {
  const area = document.getElementById("fileTargets");
  const sample = "/tmp/confidential_memo_" + Math.floor(Math.random() * 1000) + ".txt";
  area.value = area.value ? area.value + "\n" + sample : sample;
}

function triggerFileBrowser() {
  const fileInput = document.getElementById("fileBrowseInput");
  if (fileInput) fileInput.click();
}

function handleFileBrowseSelect(event) {
  const files = event.target.files;
  if (!files || files.length === 0) return;
  const area = document.getElementById("fileTargets");
  const existing = area.value.trim() ? area.value.trim().split("\n") : [];

  for (let i = 0; i < files.length; i++) {
    // Browser provides file name or relative webkit path
    const p = files[i].webkitRelativePath || files[i].name;
    if (!existing.includes(p)) existing.push(p);
  }
  area.value = existing.join("\n");
}

async function startFileErase() {
  const lines = document.getElementById("fileTargets").value.split("\n")
    .map(l => l.trim())
    .filter(l => l.length > 0);

  if (lines.length === 0) {
    alert("Please enter at least one file or folder path to sanitize.");
    return;
  }

  const patternSelectVal = document.getElementById("filePattern").value;
  let pattern = "zero";
  let passes = 1;
  if (patternSelectVal.includes("_")) {
    const parts = patternSelectVal.split("_");
    pattern = parts[0];
    passes = parseInt(parts[1], 10) || 1;
  } else {
    pattern = patternSelectVal;
  }

  const operator_id = document.getElementById("fileOperator").value.trim() || "op-forensic";
  const organization = document.getElementById("fileOrganization").value.trim() || "Digital Forensics & Data Sanitization Lab";

  // Advanced options
  const key_path = (document.getElementById("fileKeyPath")?.value || "").trim() || null;
  const key_file_el = document.getElementById("fileKeyUpload");
  let key_data = null;
  if (key_file_el && key_file_el.files && key_file_el.files.length > 0) {
    key_data = await readFileAsText(key_file_el.files[0]);
  }

  const out_dir = (document.getElementById("fileOutDir")?.value || "").trim() || null;
  const verify_samples = parseInt(document.getElementById("fileVerifySamples")?.value, 10) || 64;
  const no_pdf = !(document.getElementById("filePdfToggle")?.checked ?? true);
  const portal_url = (document.getElementById("filePortalUrl")?.value || "").trim() || null;

  document.getElementById("fileResultCard").classList.remove("active");
  const fileBadge = document.getElementById("fileStatusBadge");
  if (fileBadge) {
    fileBadge.className = "badge badge-cyan";
    fileBadge.textContent = "STATUS: RUNNING";
  }
  setHeaderJobStatus("RUNNING", "running");

  try {
    const res = await fetch("/api/erase-files", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-S0-Auth-Token": getAuthToken(),
      },
      body: JSON.stringify({
        targets: lines,
        passes,
        pattern,
        operator_id,
        organization,
        key_path,
        key_data,
        out_dir,
        no_pdf,
        verify_samples,
        portal_url,
      })
    });
    const data = await res.json();
    if (data.job_id) {
      trackJob(data.job_id, "fileStatusBadge", "fileLog", onFileEraseDone);
    } else {
      alert(data.detail || "Error starting file erase");
      if (fileBadge) {
        fileBadge.className = "badge badge-red";
        fileBadge.textContent = "STATUS: ERROR";
      }
      setHeaderJobStatus("ERROR", "error");
    }
  } catch (err) {
    alert("Failed to trigger file erasure: " + err);
    setHeaderJobStatus("ERROR", "error");
  }
}

function onFileEraseDone(job) {
  const resCard = document.getElementById("fileResultCard");
  const actionBox = document.getElementById("fileActionButtons");
  const details = document.getElementById("fileResultDetails");
  resCard.classList.add("active");
  actionBox.innerHTML = "";

  if (job.result) {
    details.textContent = `Batch completed: ${job.result.successful_files}/${job.result.total_files} files sanitized (${job.result.total_bytes} bytes). Inode timestamps zeroed, directory entries scrambled.`;
    if (job.result.cert_filename) {
      const btn = document.createElement("a");
      btn.className = "btn btn-secondary btn-sm";
      btn.href = `/api/download/${job.id}/${job.result.cert_filename}`;
      btn.textContent = "Download JSON Certificate";
      actionBox.appendChild(btn);
    }
    if (job.result.pdf_filename) {
      const btnPdf = document.createElement("a");
      btnPdf.className = "btn btn-primary btn-sm";
      btnPdf.href = `/api/download/${job.id}/${job.result.pdf_filename}`;
      btnPdf.textContent = "Download PDF Certificate";
      actionBox.appendChild(btnPdf);
    }
    renderDemoKeyNotice(actionBox, job.demo_key_warning);
  }
}

// --- Module 3: Forensic File Carver ---
function initCarverCheckboxes() {
  const grid = document.getElementById("carverExtGrid");
  if (!grid) return;
  grid.innerHTML = "";

  CARVER_SIGNATURES.forEach(sig => {
    const label = document.createElement("label");
    label.className = "ext-checkbox-label";
    label.title = `${sig.name} (${sig.cat})`;

    const cb = document.createElement("input");
    cb.type = "checkbox";
    cb.value = sig.ext;
    cb.checked = true; // default all checked
    cb.addEventListener("change", syncExtCheckboxesToInput);

    label.appendChild(cb);
    label.appendChild(document.createTextNode(sig.ext.toUpperCase()));
    grid.appendChild(label);
  });
}

function syncExtCheckboxesToInput() {
  const cbs = document.querySelectorAll("#carverExtGrid input[type='checkbox']");
  const selected = [];
  cbs.forEach(cb => {
    if (cb.checked) selected.push(cb.value);
  });
  document.getElementById("carveExts").value = selected.join(",");
}

function syncInputToExtCheckboxes() {
  const val = document.getElementById("carveExts").value.toLowerCase();
  const current = val.split(",").map(s => s.trim()).filter(s => s);
  const cbs = document.querySelectorAll("#carverExtGrid input[type='checkbox']");
  cbs.forEach(cb => {
    cb.checked = current.includes(cb.value);
  });
}

function setCarvePreset(type, el) {
  document.querySelectorAll(".chip").forEach(c => c.classList.remove("active"));
  if (el) el.classList.add("active");

  const input = document.getElementById("carveExts");
  if (type === "all") {
    input.value = CARVER_SIGNATURES.map(s => s.ext).join(",");
  } else if (type === "images") {
    input.value = "jpg,png,gif,bmp";
  } else if (type === "docs") {
    input.value = "pdf,sqlite,pcap,pcapng";
  } else if (type === "archives") {
    input.value = "zip,gz,7z";
  } else if (type === "audio") {
    input.value = "mp3,wav,flac,ogg";
  } else if (type === "none") {
    input.value = "";
  }
  syncInputToExtCheckboxes();
}

let customSigCounter = 0;

function addCustomSigRow(name = "", ext = "", cat = "custom", headerHex = "", footerHex = "", minSize = 32, maxSize = 52428800) {
  customSigCounter++;
  const list = document.getElementById("customSigList");
  if (!list) return;

  const card = document.createElement("div");
  card.className = "custom-sig-card";
  card.id = `customSigRow_${customSigCounter}`;
  card.innerHTML = `
    <div class="custom-sig-card-header">
      <span class="custom-sig-card-title">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="16"></line><line x1="8" y1="12" x2="16" y2="12"></line></svg>
        Signature #${customSigCounter}
      </span>
      <button type="button" class="btn-remove-sig" onclick="removeCustomSigRow('${card.id}')" title="Remove Signature">&times; Remove</button>
    </div>
    <div class="custom-sig-grid">
      <div>
        <label style="font-size: 0.68rem; color: var(--text-dim); display: block; margin-bottom: 2px;">Format Name:</label>
        <input type="text" class="sig-name" placeholder="e.g. Custom Container" value="${escapeHtml(name)}">
      </div>
      <div>
        <label style="font-size: 0.68rem; color: var(--text-dim); display: block; margin-bottom: 2px;">Ext (no dot):</label>
        <input type="text" class="sig-ext" placeholder="e.g. dat" value="${escapeHtml(ext)}" onchange="onCustomSigExtChange(this)">
      </div>
      <div>
        <label style="font-size: 0.68rem; color: var(--text-dim); display: block; margin-bottom: 2px;">Category:</label>
        <select class="sig-cat">
          <option value="custom" ${cat === 'custom' ? 'selected' : ''}>Custom</option>
          <option value="document" ${cat === 'document' ? 'selected' : ''}>Document</option>
          <option value="image" ${cat === 'image' ? 'selected' : ''}>Image</option>
          <option value="archive" ${cat === 'archive' ? 'selected' : ''}>Archive</option>
          <option value="audio" ${cat === 'audio' ? 'selected' : ''}>Audio</option>
          <option value="video" ${cat === 'video' ? 'selected' : ''}>Video</option>
          <option value="executable" ${cat === 'executable' ? 'selected' : ''}>Executable</option>
        </select>
      </div>
    </div>
    <div class="custom-sig-hex-grid">
      <div>
        <label style="font-size: 0.68rem; color: var(--text-dim); display: block; margin-bottom: 2px;">Header Magic Bytes (Hex, required):</label>
        <input type="text" class="sig-header mono-hex" placeholder="e.g. 53 45 43 55 (or 53454355)" value="${escapeHtml(headerHex)}">
      </div>
      <div>
        <label style="font-size: 0.68rem; color: var(--text-dim); display: block; margin-bottom: 2px;">Footer Trailer Bytes (Hex, optional):</label>
        <input type="text" class="sig-footer mono-hex" placeholder="e.g. 00 00 45 4F 46" value="${escapeHtml(footerHex)}">
      </div>
    </div>
  `;
  list.appendChild(card);
}

function removeCustomSigRow(rowId) {
  const el = document.getElementById(rowId);
  if (el) el.remove();
}

function onCustomSigExtChange(inputEl) {
  const ext = (inputEl.value || "").trim().toLowerCase().replace(/^\./, "");
  if (!ext) return;
  const filterInput = document.getElementById("carveExts");
  if (!filterInput) return;
  const current = filterInput.value.split(",").map(e => e.trim().toLowerCase()).filter(Boolean);
  if (!current.includes(ext)) {
    current.push(ext);
    filterInput.value = current.join(",");
    syncInputToExtCheckboxes();
  }
}

function collectCustomSignatures() {
  const rows = document.querySelectorAll("#customSigList .custom-sig-card");
  const sigs = [];
  rows.forEach(row => {
    const name = (row.querySelector(".sig-name")?.value || "").trim() || "Custom Signature";
    const ext = (row.querySelector(".sig-ext")?.value || "").trim().toLowerCase().replace(/^\./, "") || "bin";
    const cat = row.querySelector(".sig-cat")?.value || "custom";
    const headerHex = (row.querySelector(".sig-header")?.value || "").trim();
    const footerHex = (row.querySelector(".sig-footer")?.value || "").trim();

    if (headerHex) {
      sigs.push({
        name,
        extension: ext,
        category: cat,
        header_hex: headerHex,
        footer_hex: footerHex || null,
        min_size: 32,
        max_size: 50 * 1024 * 1024
      });
    }
  });
  return sigs;
}

async function startCarve() {
  const target = document.getElementById("carveTargetSelect").value;
  if (!target) {
    alert("Please select a target image or device to carve.");
    return;
  }

  const exts = document.getElementById("carveExts").value.split(",").map(e => e.trim()).filter(e => e);
  const min_confidence = parseInt(document.getElementById("carveMinConf").value, 10) || 50;

  const operator_id = document.getElementById("carveOperator").value.trim() || "op-forensic";
  const organization = document.getElementById("carveOrganization").value.trim() || "Digital Forensics & Data Sanitization Lab";
  const out_dir = (document.getElementById("carveOutDir")?.value || "").trim() || null;
  const custom_signatures = collectCustomSignatures();

  // Custom key
  const key_path = (document.getElementById("carveKeyPath")?.value || "").trim() || null;
  const key_file_el = document.getElementById("carveKeyUpload");
  let key_data = null;
  if (key_file_el && key_file_el.files && key_file_el.files.length > 0) {
    key_data = await readFileAsText(key_file_el.files[0]);
  }

  document.getElementById("carveResultCard").classList.remove("active");
  const carveBadge = document.getElementById("carveStatusBadge");
  if (carveBadge) {
    carveBadge.className = "badge badge-cyan";
    carveBadge.textContent = "STATUS: SCANNING";
  }
  setHeaderJobStatus("RUNNING", "running");

  try {
    const res = await fetch("/api/carve", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-S0-Auth-Token": getAuthToken(),
      },
      body: JSON.stringify({
        target,
        extensions: exts,
        min_confidence,
        operator_id,
        organization,
        out_dir,
        key_path,
        key_data,
        custom_signatures,
      })
    });
    const data = await res.json();
    if (data.job_id) {
      trackJob(data.job_id, "carveStatusBadge", "carveLog", onCarveDone);
    } else {
      alert(data.detail || "Error starting carver");
      if (carveBadge) {
        carveBadge.className = "badge badge-red";
        carveBadge.textContent = "STATUS: ERROR";
      }
      setHeaderJobStatus("ERROR", "error");
    }
  } catch (err) {
    alert("Failed to start carving session: " + err);
    setHeaderJobStatus("ERROR", "error");
  }
}

function onCarveDone(job) {
  const resCard = document.getElementById("carveResultCard");
  const title = document.getElementById("carveSummaryTitle");
  const btnBox = document.getElementById("carveManifestBtnContainer");
  const tbody = document.getElementById("carvedFilesTableBody");
  resCard.classList.add("active");
  btnBox.innerHTML = "";
  tbody.innerHTML = "";

  if (job.result) {
    title.textContent = `RECOVERED ${job.result.files_recovered} EVIDENCE ARTIFACTS (${job.result.candidates_found} candidates evaluated)`;
    if (job.result.manifest_filename) {
      const btn = document.createElement("a");
      btn.className = "btn btn-primary btn-sm";
      btn.href = `/api/download/${job.id}/${job.result.manifest_filename}`;
      btn.textContent = "Download Signed Manifest";
      btnBox.appendChild(btn);
    }
    renderDemoKeyNotice(btnBox, job.demo_key_warning);

    const files = job.result.carved_files || [];
    if (files.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-dim);">No artifacts recovered matching confidence threshold.</td></tr>';
    } else {
      files.forEach(f => {
        const tr = document.createElement("tr");
        const confBadge = f.conf >= 75 ? "badge-green" : (f.conf >= 50 ? "badge-cyan" : "badge-amber");

        const tdId = document.createElement("td");
        tdId.className = "code-cell";
        const strongId = document.createElement("strong");
        strongId.textContent = f.id || "";
        tdId.appendChild(strongId);

        const tdExt = document.createElement("td");
        const spanExt = document.createElement("span");
        spanExt.className = "badge badge-purple";
        spanExt.textContent = (f.ext || "").toUpperCase();
        tdExt.appendChild(spanExt);

        const tdSize = document.createElement("td");
        tdSize.className = "code-cell";
        tdSize.textContent = `${((f.size || 0) / 1024).toFixed(1)} KB`;

        const tdConf = document.createElement("td");
        const spanConf = document.createElement("span");
        spanConf.className = `badge ${confBadge}`;
        spanConf.textContent = `${f.conf || 0}%`;
        tdConf.appendChild(spanConf);

        const tdHash = document.createElement("td");
        tdHash.className = "code-cell";
        tdHash.style.color = "var(--text-dim)";
        tdHash.textContent = f.sha256 ? f.sha256.substring(0, 16) + "..." : "—";
        if (f.sha256) tdHash.title = f.sha256;

        const tdAction = document.createElement("td");
        const btnExtract = document.createElement("a");
        btnExtract.className = "btn btn-secondary btn-sm";
        btnExtract.style.cssText = "padding: 3px 8px; font-size: 0.72rem;";
        btnExtract.textContent = "Extract";
        btnExtract.href = `/api/download/${encodeURIComponent(job.id)}/${encodeURIComponent(f.filename || "")}`;
        tdAction.appendChild(btnExtract);

        tr.appendChild(tdId);
        tr.appendChild(tdExt);
        tr.appendChild(tdSize);
        tr.appendChild(tdConf);
        tr.appendChild(tdHash);
        tr.appendChild(tdAction);

        tbody.appendChild(tr);
      });
    }
  }
}

// --- Module 4: Forensic Imager & Cloner ---
function updateClonePrompt() {
  const dest = document.getElementById("imageDestInput").value.trim();
  const promptEl = document.getElementById("cloneConfirmPromptPath");
  if (promptEl) promptEl.textContent = dest || "destination block device path";
}

function toggleCloneWarning() {
  const isClone = document.getElementById("imageIsClone").checked;
  const box = document.getElementById("cloneWarningBox");
  box.style.display = isClone ? "block" : "none";
  if (isClone) updateClonePrompt();
}

async function startImaging() {
  const source = document.getElementById("imageSourceSelect").value.trim();
  const destination = document.getElementById("imageDestInput").value.trim();
  const block_size = parseInt(document.getElementById("imageBlockSize").value, 10) || 1048576;
  const no_recovery = !document.getElementById("imageFaultTol").checked;
  const is_clone = document.getElementById("imageIsClone").checked;
  const confirm_text = document.getElementById("cloneConfirmInput").value.trim();

  const operator_id = document.getElementById("imageOperator")?.value.trim() || "op-forensic";
  const organization = document.getElementById("imageOrganization")?.value.trim() || "Digital Forensics & Incident Response Lab";
  const out_dir = (document.getElementById("imageOutDir")?.value || "").trim() || null;

  const key_path = (document.getElementById("imageKeyPath")?.value || "").trim() || null;
  const key_file_el = document.getElementById("imageKeyUpload");
  let key_data = null;
  if (key_file_el && key_file_el.files && key_file_el.files.length > 0) {
    key_data = await readFileAsText(key_file_el.files[0]);
  }

  if (!source) {
    alert("Please select a source drive or forensic image.");
    return;
  }
  if (!destination) {
    alert("Please enter a destination image file or block device.");
    return;
  }
  if (source === destination) {
    alert("Source and destination cannot be the same path.");
    return;
  }
  if (is_clone && confirm_text !== destination) {
    alert(`Safety check: Please type the exact destination path "${destination}" to confirm cloning.`);
    return;
  }

  document.getElementById("imageResultCard").classList.remove("active");
  const imageBadge = document.getElementById("imageStatusBadge");
  if (imageBadge) {
    imageBadge.className = "badge badge-cyan";
    imageBadge.textContent = "STATUS: RUNNING";
  }
  setHeaderJobStatus("RUNNING", "running");

  try {
    const res = await fetch("/api/image", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-S0-Auth-Token": getAuthToken(),
      },
      body: JSON.stringify({
        source,
        destination,
        block_size,
        no_recovery,
        is_clone,
        confirm_text,
        operator_id,
        organization,
        out_dir,
        key_path,
        key_data,
      })
    });
    const data = await res.json();
    if (data.job_id) {
      trackJob(data.job_id, "imageStatusBadge", "imageLog", onImagingDone);
    } else {
      alert(data.detail || "Error starting acquisition");
      if (imageBadge) {
        imageBadge.className = "badge badge-red";
        imageBadge.textContent = "STATUS: ERROR";
      }
      setHeaderJobStatus("ERROR", "error");
    }
  } catch (err) {
    alert("Failed to communicate with imager engine: " + err);
    setHeaderJobStatus("ERROR", "error");
  }
}

function onImagingDone(job) {
  const resCard = document.getElementById("imageResultCard");
  const actionBox = document.getElementById("imageActionButtons");
  resCard.classList.add("active");
  actionBox.innerHTML = "";

  if (job.result) {
    const r = job.result;
    const mbCopied = ((r.bytes_copied || 0) / (1024 * 1024)).toFixed(1);
    document.getElementById("imageBytesCopiedVal").textContent = `${mbCopied} MiB (${(r.bytes_copied || 0).toLocaleString()} bytes)`;
    const speed = (r.speed_mbps || 0).toFixed(1);
    const dur = (r.duration_seconds || 0).toFixed(2);
    document.getElementById("imageSpeedTimeVal").textContent = `${speed} MB/s • ${dur}s elapsed`;
    document.getElementById("imageBadSectorsVal").textContent = r.bad_sectors_count || 0;
    document.getElementById("imageSha256Val").textContent = r.source_sha256 || "—";
    document.getElementById("imageMd5Val").textContent = r.source_md5 || "—";

    if (r.manifest_filename) {
      const btnManifest = document.createElement("a");
      btnManifest.className = "btn btn-secondary btn-sm";
      btnManifest.href = `/api/download/${job.id}/${r.manifest_filename}`;
      btnManifest.textContent = "Download Manifest";
      actionBox.appendChild(btnManifest);
    }
    if (r.cert_filename) {
      const btnCert = document.createElement("a");
      btnCert.className = "btn btn-primary btn-sm";
      btnCert.href = `/api/download/${job.id}/${r.cert_filename}`;
      btnCert.textContent = "Download Certificate";
      actionBox.appendChild(btnCert);
    }
    renderDemoKeyNotice(actionBox, job.demo_key_warning);
  }
}

// --- Job Poller Engine ---
function trackJob(jobId, statusBadgeId, logId, onDoneCallback) {
  currentJobId = jobId;
  const badge = statusBadgeId ? document.getElementById(statusBadgeId) : null;
  const logEl = document.getElementById(logId);
  setHeaderJobStatus("RUNNING", "running");

  const timer = setInterval(async () => {
    try {
      const res = await fetch(`/api/job/${jobId}`);
      if (!res.ok) return;
      const data = await res.json();

      if (data.log && data.log.length > 0) {
        logEl.textContent = data.log.join("\n");
        logEl.scrollTop = logEl.scrollHeight;
      }

      if (data.status === "done" || data.status === "error") {
        clearInterval(timer);
        if (data.status === "done") {
          if (badge) {
            badge.className = "badge badge-green";
            badge.textContent = "STATUS: COMPLETE";
          }
          setHeaderJobStatus("COMPLETE", "success");
          setTimeout(() => setHeaderJobStatus("IDLE", "idle"), 8000);
          if (onDoneCallback) onDoneCallback({ id: jobId, result: data.result, demo_key_warning: data.demo_key_warning });
        } else {
          if (badge) {
            badge.className = "badge badge-red";
            badge.textContent = "STATUS: FAILED";
          }
          setHeaderJobStatus("FAILED", "error");
          setTimeout(() => setHeaderJobStatus("IDLE", "idle"), 8000);
        }
      }
    } catch (e) {
      console.warn("Poll job warning:", e);
    }
  }, 600);
}

// --- Module 5: Blockchain Audit Ledger ---
async function loadAuditBlocks() {
  try {
    const res = await fetch("/api/audit/blocks?limit=150");
    const data = await res.json();
    allBlocksCache = data.blocks || [];
    renderAuditTable(allBlocksCache);
  } catch (e) {
    console.error("Failed to load audit blocks", e);
  }
}

function renderAuditTable(blocks) {
  const tbody = document.getElementById("auditTableBody");
  const countEl = document.getElementById("auditBlockCount");
  if (countEl) countEl.textContent = blocks.length;

  tbody.innerHTML = "";
  if (blocks.length === 0) {
    tbody.innerHTML = '<tr><td colspan="8" style="text-align: center; color: var(--text-dim);">No records in audit ledger yet.</td></tr>';
    return;
  }

  blocks.forEach(b => {
    const tr = document.createElement("tr");
    let opBadge = "badge-cyan";
    if (b.operation === "FILE_ERASE") opBadge = "badge-amber";
    else if (b.operation === "FILE_CARVE") opBadge = "badge-purple";
    else if (b.operation === "GENESIS") opBadge = "badge-green";

    const prevShort = b.prev_hash ? b.prev_hash.substring(0, 12) + '...' : '—';
    const blockShort = b.block_hash ? b.block_hash.substring(0, 12) + '...' : '—';

    const tdIdx = document.createElement("td");
    tdIdx.className = "code-cell";
    const strongIdx = document.createElement("strong");
    strongIdx.textContent = `#${b.index}`;
    tdIdx.appendChild(strongIdx);

    const tdTime = document.createElement("td");
    tdTime.className = "code-cell";
    tdTime.textContent = b.timestamp || "";

    const tdOp = document.createElement("td");
    const spanOp = document.createElement("span");
    spanOp.className = `badge ${opBadge}`;
    spanOp.textContent = b.operation || "";
    tdOp.appendChild(spanOp);

    const tdTarget = document.createElement("td");
    tdTarget.className = "code-cell";
    tdTarget.style.cssText = "overflow: hidden; text-overflow: ellipsis; white-space: nowrap;";
    tdTarget.textContent = b.target || "";
    if (b.target) tdTarget.title = b.target;

    const tdOpId = document.createElement("td");
    tdOpId.textContent = b.operator || "";

    const tdPrev = document.createElement("td");
    tdPrev.className = "code-cell";
    tdPrev.style.cssText = "color: var(--text-dim); overflow: hidden; text-overflow: ellipsis; white-space: nowrap;";
    tdPrev.textContent = prevShort;
    if (b.prev_hash) tdPrev.title = b.prev_hash;

    const tdBlock = document.createElement("td");
    tdBlock.className = "code-cell";
    tdBlock.style.cssText = "color: #38bdf8; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;";
    tdBlock.textContent = blockShort;
    if (b.block_hash) tdBlock.title = b.block_hash;

    const tdAction = document.createElement("td");
    tdAction.style.textAlign = "center";
    const btnInspect = document.createElement("button");
    btnInspect.className = "btn btn-secondary btn-sm";
    btnInspect.style.cssText = "padding: 3px 8px; font-size: 0.72rem;";
    btnInspect.textContent = "Inspect";
    btnInspect.onclick = () => inspectBlock(b.index);
    tdAction.appendChild(btnInspect);

    tr.appendChild(tdIdx);
    tr.appendChild(tdTime);
    tr.appendChild(tdOp);
    tr.appendChild(tdTarget);
    tr.appendChild(tdOpId);
    tr.appendChild(tdPrev);
    tr.appendChild(tdBlock);
    tr.appendChild(tdAction);

    tbody.appendChild(tr);
  });
}

function applyAuditFilters() {
  const opFilter = document.getElementById("auditFilterOp").value;
  const search = document.getElementById("auditSearch").value.toLowerCase().trim();

  const filtered = allBlocksCache.filter(b => {
    const matchesOp = (opFilter === "ALL" || b.operation === opFilter);
    const matchesSearch = !search ||
      (b.target && b.target.toLowerCase().includes(search)) ||
      (b.block_hash && b.block_hash.toLowerCase().includes(search)) ||
      (b.operator && b.operator.toLowerCase().includes(search));
    return matchesOp && matchesSearch;
  });
  renderAuditTable(filtered);
}

async function verifyLedger() {
  const banner = document.getElementById("auditVerifyBanner");
  banner.style.display = "block";
  banner.className = "badge badge-cyan";
  banner.style.width = "100%";
  banner.textContent = "Auditing cryptographic SHA-256 hash chain and block continuity...";

  try {
    const res = await fetch("/api/audit/verify");
    const data = await res.json();
    if (data.is_valid) {
      banner.style.background = "rgba(16, 185, 129, 0.15)";
      banner.style.border = "1px solid rgba(16, 185, 129, 0.35)";
      banner.style.color = "#34d399";
      banner.innerHTML = `<span style="display:inline-flex;align-items:center;gap:6px;"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg> <strong>CRYPTOGRAPHIC AUDIT CHAIN VALID:</strong></span> ${escapeHtml(data.reason)} (${parseInt(data.total_blocks, 10) || 0} blocks verified unbroken from genesis)`;
    } else {
      banner.style.background = "rgba(239, 68, 68, 0.15)";
      banner.style.border = "1px solid rgba(239, 68, 68, 0.35)";
      banner.style.color = "#f87171";
      banner.innerHTML = `<span style="display:inline-flex;align-items:center;gap:6px;"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg> <strong>INTEGRITY VIOLATION DETECTED:</strong></span> ${escapeHtml(data.reason)}`;
    }
  } catch (err) {
    banner.style.color = "#f87171";
    banner.textContent = "Verification request failed: " + err;
  }
}

function inspectBlock(idx) {
  const b = allBlocksCache.find(item => item.index === idx);
  if (!b) return;

  document.getElementById("modalTitle").textContent = `Block Inspector // #${b.index} [${b.operation}]`;
  document.getElementById("modalContent").textContent = JSON.stringify(b, null, 2);
  document.getElementById("inspectorModal").classList.add("active");
}

function closeInspector() {
  document.getElementById("inspectorModal").classList.remove("active");
}

// Light / Dark Mode Theme Controller
function initTheme() {
  let saved = "dark";
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
  const lbl = document.getElementById("themeToggleLabel");
  if (lbl) {
    lbl.textContent = theme === "light" ? "Dark" : "Light";
  }
}

function toggleTheme() {
  const current = document.documentElement.getAttribute("data-theme") || "dark";
  applyTheme(current === "dark" ? "light" : "dark");
}

// Initialize on DOM ready
window.addEventListener("DOMContentLoaded", async () => {
  initTheme();
  initCarverCheckboxes();
  await loadAppConfig();
  await loadDevices();
  handleHashRouting();
  readUrlParams();
});

window.addEventListener("hashchange", handleHashRouting);
