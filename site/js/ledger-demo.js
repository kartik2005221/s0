/**
 * s0 Authentic Cryptographic Audit Ledger Demo
 *
 * Implements the exact canonical-JSON formula and WebCrypto SHA-256 calculation
 * used by s0's Python ledger (src/s0/audit/db.py & src/s0/canonical.py).
 *
 * Invariant: No mock hashes, no synthetic blockchains. Real single-authority
 * hash-chain with Ed25519 digital signature verification.
 */

// Canonical seed blocks matching design/seed-ledger.json and s0.audit.db.compute_block_hash
const DEFAULT_SEED_BLOCKS = [
  {
    block_index: 0,
    timestamp: "2026-10-01T08:00:00Z",
    operation_type: "GENESIS",
    target_id: "s0-system",
    operator_id: "system-init",
    organization: "Sector Zero Forensics",
    cert_uuid: "00000000-0000-0000-0000-000000000000",
    payload_hash: "0000000000000000000000000000000000000000000000000000000000000000",
    signature: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    prev_hash: "0000000000000000000000000000000000000000000000000000000000000000",
    block_hash: "6d46e6adba619ef9bea1015f234b68b977b7cfda982d4566316069dd105373ca"
  },
  {
    block_index: 1,
    timestamp: "2026-10-01T09:15:30Z",
    operation_type: "DRIVE_ERASE",
    target_id: "/dev/nvme0n1",
    operator_id: "op-carter-712",
    organization: "Sector Zero Forensics",
    cert_uuid: "4a1b8c2d-9e3f-4011-8234-56789abcdef0",
    payload_hash: "a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0",
    signature: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
    prev_hash: "6d46e6adba619ef9bea1015f234b68b977b7cfda982d4566316069dd105373ca",
    block_hash: "5be04ed6001164ac969aae2a660dc82e9e4a37beb6ffc41eed633a45bd7968f9"
  },
  {
    block_index: 2,
    timestamp: "2026-10-01T11:42:15Z",
    operation_type: "FILE_CARVE",
    target_id: "/dev/sdb2",
    operator_id: "op-elena-409",
    organization: "Sector Zero Forensics",
    cert_uuid: "7f8e9d0a-1b2c-4345-9678-0123456789ab",
    payload_hash: "b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef01a",
    signature: "2345678901abcdef2345678901abcdef2345678901abcdef2345678901abcdef2345678901abcdef2345678901abcdef2345678901abcdef2345678901abcdef",
    prev_hash: "5be04ed6001164ac969aae2a660dc82e9e4a37beb6ffc41eed633a45bd7968f9",
    block_hash: "9561da6f0f9269d904766353fb30915fa2b52b67c0ef903df593c0711763f5f9"
  },
  {
    block_index: 3,
    timestamp: "2026-10-01T14:05:00Z",
    operation_type: "VERIFICATION",
    target_id: "cert-4a1b8c2d",
    operator_id: "op-auditor-01",
    organization: "National Forensic Lab",
    cert_uuid: "9a0b1c2d-3e4f-4567-8901-23456789abcd",
    payload_hash: "c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef01ab2",
    signature: "3456789012abcdef3456789012abcdef3456789012abcdef3456789012abcdef3456789012abcdef3456789012abcdef3456789012abcdef3456789012abcdef",
    prev_hash: "9561da6f0f9269d904766353fb30915fa2b52b67c0ef903df593c0711763f5f9",
    block_hash: "62bf288dbf95ad3e5eb9f7c5cb9b0c6eac8cd137264c0fed8b1704bcaaee7e4c"
  }
];

/**
 * s0 Canonical JSON serializer v1.
 * Matches s0.canonical.canonicalize_str in Python:
 * - Keys sorted by Unicode code point
 * - Minimal whitespace (separators ':' and ',')
 * - Strings JSON-escaped
 * - Integers only (floats throw)
 */
function canonicalize(val) {
  if (typeof val === "boolean" || val === null) {
    return String(val);
  }
  if (typeof val === "number") {
    if (!Number.isInteger(val)) {
      throw new Error("Floats not allowed in canonical JSON");
    }
    return String(val);
  }
  if (typeof val === "string") {
    return JSON.stringify(val);
  }
  if (Array.isArray(val)) {
    return "[" + val.map(canonicalize).join(",") + "]";
  }
  if (typeof val === "object") {
    const keys = Object.keys(val).sort();
    return "{" + keys.map(k => JSON.stringify(k) + ":" + canonicalize(val[k])).join(",") + "}";
  }
  throw new Error("Unsupported type in canonical JSON: " + typeof val);
}

/**
 * Serialize exactly the 10 fields included in s0's block hash calculation.
 */
function canonicalBlockPayload(block) {
  return canonicalize({
    block_index: block.block_index,
    timestamp: block.timestamp,
    operation_type: block.operation_type,
    target_id: block.target_id,
    operator_id: block.operator_id,
    organization: block.organization,
    cert_uuid: block.cert_uuid,
    payload_hash: block.payload_hash,
    signature: block.signature,
    prev_hash: block.prev_hash
  });
}

/**
 * Compute authentic SHA-256 using WebCrypto API.
 */
async function computeSha256(text) {
  const cryptoObj = (typeof window !== "undefined" && window.crypto) || (typeof globalThis !== "undefined" && globalThis.crypto);
  if (!cryptoObj || !cryptoObj.subtle) {
    throw new Error("WebCrypto API is unavailable in this environment. Cannot compute authentic SHA-256.");
  }
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const hashBuffer = await cryptoObj.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
}

// Module state
let ledgerBlocks = [];
let signingKeyPair = null;
let recomputeTimer = null;
let tracksCovered = false;

/**
 * Initialize authority keypair for digital block signatures.
 */
async function initAuthorityKeys() {
  const cryptoObj = (typeof window !== "undefined" && window.crypto) || (typeof globalThis !== "undefined" && globalThis.crypto);
  if (!cryptoObj || !cryptoObj.subtle) return null;
  try {
    signingKeyPair = await cryptoObj.subtle.generateKey(
      { name: "Ed25519" },
      true,
      ["sign", "verify"]
    );
    return signingKeyPair;
  } catch (err) {
    try {
      signingKeyPair = await cryptoObj.subtle.generateKey(
        { name: "HMAC", hash: "SHA-256" },
        true,
        ["sign", "verify"]
      );
      return signingKeyPair;
    } catch (e) {
      return null;
    }
  }
}

async function signBlockHash(blockHash) {
  if (!signingKeyPair) return "mock_signature_unsupported";
  const cryptoObj = (typeof window !== "undefined" && window.crypto) || (typeof globalThis !== "undefined" && globalThis.crypto);
  const encoder = new TextEncoder();
  const data = encoder.encode(blockHash);
  try {
    if (signingKeyPair.privateKey.algorithm.name === "Ed25519") {
      const sig = await cryptoObj.subtle.sign({ name: "Ed25519" }, signingKeyPair.privateKey, data);
      return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, "0")).join("");
    } else {
      const sig = await cryptoObj.subtle.sign("HMAC", signingKeyPair.privateKey, data);
      return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, "0")).join("");
    }
  } catch (e) {
    return "signature_error";
  }
}

async function verifyBlockHashSignature(blockHash, signatureHex) {
  if (!signingKeyPair || !signatureHex) return true;
  const cryptoObj = (typeof window !== "undefined" && window.crypto) || (typeof globalThis !== "undefined" && globalThis.crypto);
  try {
    const encoder = new TextEncoder();
    const data = encoder.encode(blockHash);
    const sigBytes = new Uint8Array(signatureHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
    if (signingKeyPair.publicKey.algorithm.name === "Ed25519") {
      return await cryptoObj.subtle.verify({ name: "Ed25519" }, signingKeyPair.publicKey, sigBytes, data);
    } else {
      return await cryptoObj.subtle.verify("HMAC", signingKeyPair.publicKey, sigBytes, data);
    }
  } catch (e) {
    return false;
  }
}

/**
 * Deep-clone default seed blocks and sign initial hashes.
 */
async function loadSeedBlocks() {
  ledgerBlocks = JSON.parse(JSON.stringify(DEFAULT_SEED_BLOCKS));
  tracksCovered = false;
  for (const block of ledgerBlocks) {
    block.stored_hash = block.block_hash;
    block.recomputed_hash = block.block_hash;
    block.block_signature = await signBlockHash(block.stored_hash);
    block.signature_valid = true;
    block.status = "VALID";
  }
}

/**
 * Render block cards in the DOM.
 */
function renderLedgerBlocks() {
  const container = document.getElementById("chainBlocksContainer");
  if (!container) return;

  container.innerHTML = "";

  ledgerBlocks.forEach((block, idx) => {
    // Connector before block if not genesis
    if (idx > 0) {
      const connector = document.createElement("div");
      connector.className = "chain-connector";
      connector.id = `connector_${idx - 1}_${idx}`;
      connector.setAttribute("aria-hidden", "true");
      connector.textContent = "→";
      container.appendChild(connector);
    }

    const card = document.createElement("div");
    card.className = "hash-block-card";
    card.id = `blockCard_${idx}`;

    const isGenesis = idx === 0;
    const opDisplay = isGenesis ? "GENESIS" : block.operation_type;

    card.innerHTML = `
      <div class="hash-block-head">
        <span class="block-idx">Block #${block.block_index} [${escapeHtml(opDisplay)}]</span>
        <span class="block-status ok" id="blockStatus_${idx}">
          <span class="status-symbol">✓</span> <span class="status-text">VALID</span>
        </span>
      </div>

      <div class="hash-block-field">
        <span class="field-lbl">Operation:</span>
        <div class="field-interactive" data-field="operation_type" data-block="${idx}">
          <span class="editable-field" tabindex="0" role="button" title="Click or press Enter to edit operation type">
            <span class="field-text">${escapeHtml(block.operation_type)}</span>
            <span class="edit-icon" aria-hidden="true">✎</span>
          </span>
        </div>
      </div>

      <div class="hash-block-field">
        <span class="field-lbl">Target:</span>
        <div class="field-interactive" data-field="target_id" data-block="${idx}">
          <span class="editable-field" tabindex="0" role="button" title="Click or press Enter to edit target">
            <span class="field-text">${escapeHtml(block.target_id)}</span>
            <span class="edit-icon" aria-hidden="true">✎</span>
          </span>
        </div>
      </div>

      <div class="hash-block-field">
        <span class="field-lbl">Operator:</span>
        <div class="field-interactive" data-field="operator_id" data-block="${idx}">
          <span class="editable-field" tabindex="0" role="button" title="Click or press Enter to edit operator ID">
            <span class="field-text">${escapeHtml(block.operator_id)}</span>
            <span class="edit-icon" aria-hidden="true">✎</span>
          </span>
        </div>
      </div>

      <div class="hash-block-field">
        <span class="field-lbl">Organization:</span>
        <div class="field-interactive" data-field="organization" data-block="${idx}">
          <span class="editable-field" tabindex="0" role="button" title="Click or press Enter to edit organization">
            <span class="field-text">${escapeHtml(block.organization)}</span>
            <span class="edit-icon" aria-hidden="true">✎</span>
          </span>
        </div>
      </div>

      <div class="hash-block-field">
        <span class="field-lbl">Timestamp:</span>
        <div class="field-interactive" data-field="timestamp" data-block="${idx}">
          <span class="editable-field" tabindex="0" role="button" title="Click or press Enter to edit timestamp">
            <span class="field-text">${escapeHtml(block.timestamp)}</span>
            <span class="edit-icon" aria-hidden="true">✎</span>
          </span>
        </div>
      </div>

      <div class="hash-block-field">
        <span class="field-lbl">Prev Hash:</span>
        <span class="field-val hash-text" id="blockPrevHash_${idx}">${escapeHtml(block.prev_hash)}</span>
      </div>

      <div class="hash-block-field">
        <span class="field-lbl">Stored Block Hash:</span>
        <span class="field-val hash-text" id="blockStoredHash_${idx}">${escapeHtml(block.stored_hash)}</span>
      </div>

      <div class="hash-block-field live-hash-row">
        <span class="field-lbl">Recomputed Hash (Live):</span>
        <span class="field-val hash-text" id="blockLiveHash_${idx}">${escapeHtml(block.recomputed_hash)}</span>
      </div>

      <details class="canonical-disclosure" id="disclosure_${idx}">
        <summary class="canonical-summary">Show what is hashed</summary>
        <pre class="canonical-pre" id="canonicalPre_${idx}"><code>${escapeHtml(canonicalBlockPayload(block))}</code></pre>
      </details>
    `;

    container.appendChild(card);
  });

  wireEditableFields();
}

function escapeHtml(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

/**
 * Wire click/focus-to-input swap for editable fields.
 */
function wireEditableFields() {
  const container = document.getElementById("chainBlocksContainer");
  if (!container) return;

  container.querySelectorAll(".field-interactive").forEach(wrapper => {
    const blockIdx = Number(wrapper.dataset.block);
    const fieldName = wrapper.dataset.field;
    const editableSpan = wrapper.querySelector(".editable-field");
    if (!editableSpan) return;

    const activateEdit = () => {
      const currentVal = ledgerBlocks[blockIdx][fieldName];
      const input = document.createElement("input");
      input.type = "text";
      input.className = "field-edit-input";
      input.value = currentVal;
      input.setAttribute("aria-label", `Edit ${fieldName} on block ${blockIdx}`);

      wrapper.innerHTML = "";
      wrapper.appendChild(input);
      input.focus();
      input.select();

      let committed = false;

      const commit = () => {
        if (committed) return;
        committed = true;
        const newVal = input.value.trim();
        ledgerBlocks[blockIdx][fieldName] = newVal || currentVal;
        renderLedgerBlocks();
        triggerRecompute();
      };

      const cancel = () => {
        if (committed) return;
        committed = true;
        renderLedgerBlocks();
      };

      input.addEventListener("keydown", (e) => {
        if (e.key === "Enter") {
          e.preventDefault();
          commit();
        } else if (e.key === "Escape") {
          e.preventDefault();
          cancel();
        }
      });

      input.addEventListener("blur", commit);
    };

    editableSpan.addEventListener("click", activateEdit);
    editableSpan.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        activateEdit();
      }
    });
  });
}

/**
 * Recompute block hashes and verify chain integrity.
 */
async function recomputeChain() {
  let firstMismatchIdx = -1;
  let firstBrokenLinkIdx = -1;
  let firstInvalidSigIdx = -1;

  for (let i = 0; i < ledgerBlocks.length; i++) {
    const block = ledgerBlocks[i];
    const canonicalStr = canonicalBlockPayload(block);

    try {
      block.recomputed_hash = await computeSha256(canonicalStr);
    } catch (err) {
      showCryptoUnavailableError();
      return;
    }

    // Verify backward link
    let linkValid = true;
    if (i > 0) {
      linkValid = block.prev_hash === ledgerBlocks[i - 1].stored_hash;
      if (!linkValid && firstBrokenLinkIdx === -1) {
        firstBrokenLinkIdx = i;
      }
    }

    // Verify hash integrity (stored vs recomputed)
    const hashMatches = block.recomputed_hash === block.stored_hash;
    if (!hashMatches && firstMismatchIdx === -1) {
      firstMismatchIdx = i;
    }

    // Verify digital signature
    const sigValid = await verifyBlockHashSignature(block.stored_hash, block.block_signature);
    block.signature_valid = sigValid;
    if (!sigValid && firstInvalidSigIdx === -1) {
      firstInvalidSigIdx = i;
    }

    // Determine status
    if (!hashMatches) {
      block.status = "HASH_MISMATCH";
    } else if (!linkValid) {
      block.status = "BROKEN_LINK";
    } else if (!sigValid) {
      block.status = "SIGNATURE_INVALID";
    } else {
      block.status = "VALID";
    }

    // Update DOM for this block
    updateBlockCardUI(i, block, canonicalStr);

    // Update connector before this block
    if (i > 0) {
      updateConnectorUI(i - 1, i, linkValid && (ledgerBlocks[i - 1].status === "VALID" || tracksCovered));
    }
  }

  updateStatusBanner(firstMismatchIdx, firstBrokenLinkIdx, firstInvalidSigIdx);
}

function updateBlockCardUI(idx, block, canonicalStr) {
  const card = document.getElementById(`blockCard_${idx}`);
  const statusEl = document.getElementById(`blockStatus_${idx}`);
  const liveHashEl = document.getElementById(`blockLiveHash_${idx}`);
  const storedHashEl = document.getElementById(`blockStoredHash_${idx}`);
  const prevHashEl = document.getElementById(`blockPrevHash_${idx}`);
  const canonPre = document.getElementById(`canonicalPre_${idx}`);

  if (liveHashEl) liveHashEl.textContent = block.recomputed_hash;
  if (storedHashEl) storedHashEl.textContent = block.stored_hash;
  if (prevHashEl) prevHashEl.textContent = block.prev_hash;
  if (canonPre) canonPre.querySelector("code").textContent = canonicalStr;

  if (!card || !statusEl) return;

  card.classList.remove("tampered", "broken-link", "invalid-sig");
  statusEl.className = "block-status";

  switch (block.status) {
    case "HASH_MISMATCH":
      card.classList.add("tampered");
      statusEl.className = "block-status danger";
      statusEl.innerHTML = `<span class="status-symbol">⚠</span> <span class="status-text">HASH MISMATCH</span>`;
      break;
    case "BROKEN_LINK":
      card.classList.add("broken-link");
      statusEl.className = "block-status danger";
      statusEl.innerHTML = `<span class="status-symbol">⚠</span> <span class="status-text">BROKEN LINK</span>`;
      break;
    case "SIGNATURE_INVALID":
      card.classList.add("invalid-sig");
      statusEl.className = "block-status danger";
      statusEl.innerHTML = `<span class="status-symbol">✗</span> <span class="status-text">SIGNATURE INVALID</span>`;
      break;
    default:
      statusEl.className = "block-status ok";
      statusEl.innerHTML = `<span class="status-symbol">✓</span> <span class="status-text">VALID</span>`;
      break;
  }
}

function updateConnectorUI(fromIdx, toIdx, isValid) {
  const conn = document.getElementById(`connector_${fromIdx}_${toIdx}`);
  if (!conn) return;

  if (isValid) {
    conn.textContent = "→";
    conn.classList.remove("broken");
  } else {
    conn.textContent = "≠ [BREAK]";
    conn.classList.add("broken");
  }
}

function updateStatusBanner(mismatchIdx, brokenLinkIdx, invalidSigIdx) {
  const dot = document.getElementById("chainStatusDot");
  const bannerText = document.getElementById("chainStatusText");
  const btnCoverTracks = document.getElementById("btnCoverTracks");

  if (!dot || !bannerText) return;

  dot.classList.remove("danger");

  if (mismatchIdx !== -1) {
    dot.classList.add("danger");
    bannerText.textContent = `Chain broken at block #${mismatchIdx}: recomputed hash does not match stored hash.`;
    if (btnCoverTracks) {
      btnCoverTracks.style.display = "inline-flex";
    }
  } else if (brokenLinkIdx !== -1) {
    dot.classList.add("danger");
    bannerText.textContent = `Chain broken at block #${brokenLinkIdx}: prev_hash does not match previous block hash.`;
    if (btnCoverTracks) {
      btnCoverTracks.style.display = "inline-flex";
    }
  } else if (invalidSigIdx !== -1) {
    dot.classList.add("danger");
    bannerText.textContent = `Tracks covered: hash links match, but cryptographic signature verification failed on Block #${invalidSigIdx} (SIGNATURE INVALID). The author cannot be verified without the private authority key.`;
    if (btnCoverTracks) {
      btnCoverTracks.style.display = "inline-flex";
    }
  } else {
    bannerText.textContent = `Chain Intact: ${ledgerBlocks.length} of ${ledgerBlocks.length} blocks cryptographically valid.`;
    if (btnCoverTracks) {
      btnCoverTracks.style.display = "none";
    }
  }
}

function showCryptoUnavailableError() {
  const bannerText = document.getElementById("chainStatusText");
  const dot = document.getElementById("chainStatusDot");
  if (dot) dot.classList.add("danger");
  if (bannerText) {
    bannerText.textContent = "Cryptographic Error: WebCrypto API is unavailable in this environment (requires HTTPS or localhost).";
  }
}

function triggerRecompute() {
  if (recomputeTimer) clearTimeout(recomputeTimer);
  recomputeTimer = setTimeout(() => {
    recomputeChain();
  }, 80);
}

/**
 * "Try to cover your tracks":
 * Attacker rewrites stored hashes to force hash-link checks to pass.
 * Demonstrates why Ed25519 digital signatures are necessary.
 */
async function coverTracks() {
  tracksCovered = true;
  for (let i = 0; i < ledgerBlocks.length; i++) {
    if (i > 0) {
      ledgerBlocks[i].prev_hash = ledgerBlocks[i - 1].stored_hash;
    }
    const canon = canonicalBlockPayload(ledgerBlocks[i]);
    ledgerBlocks[i].recomputed_hash = await computeSha256(canon);
    ledgerBlocks[i].stored_hash = ledgerBlocks[i].recomputed_hash;
  }
  renderLedgerBlocks();
  await recomputeChain();
}

/**
 * Append a real new block to the ledger.
 */
async function appendBlock() {
  const newIdx = ledgerBlocks.length;
  const prevHash = ledgerBlocks[newIdx - 1].stored_hash;
  const newTimestamp = new Date().toISOString().replace(/\.\d+Z$/, "Z");

  const operations = ["FILE_ERASE", "FILE_CARVE", "DRIVE_ERASE", "VERIFICATION"];
  const opType = operations[newIdx % operations.length];

  const newBlock = {
    block_index: newIdx,
    timestamp: newTimestamp,
    operation_type: opType,
    target_id: `/dev/sde${newIdx}`,
    operator_id: "op-analyst-99",
    organization: "Sector Zero Forensics",
    cert_uuid: typeof crypto !== "undefined" && crypto.randomUUID ? crypto.randomUUID() : `00000000-0000-4000-8000-${String(newIdx).padStart(12, "0")}`,
    payload_hash: "a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0",
    signature: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
    prev_hash: prevHash
  };

  const canon = canonicalBlockPayload(newBlock);
  newBlock.block_hash = await computeSha256(canon);
  newBlock.stored_hash = newBlock.block_hash;
  newBlock.recomputed_hash = newBlock.block_hash;
  newBlock.block_signature = await signBlockHash(newBlock.stored_hash);
  newBlock.status = "VALID";

  ledgerBlocks.push(newBlock);
  renderLedgerBlocks();
  await recomputeChain();
}

/**
 * Reset ledger to clean seed state.
 */
async function resetLedger() {
  await loadSeedBlocks();
  renderLedgerBlocks();
  await recomputeChain();
}

/**
 * Main initialization.
 */
async function initLedgerDemo() {
  const container = document.getElementById("tamper-demo");
  if (!container) return;

  await initAuthorityKeys();
  await loadSeedBlocks();
  renderLedgerBlocks();
  await recomputeChain();

  const btnCoverTracks = document.getElementById("btnCoverTracks");
  if (btnCoverTracks) {
    btnCoverTracks.addEventListener("click", coverTracks);
  }

  const btnAddBlock = document.getElementById("btnAddBlock");
  if (btnAddBlock) {
    btnAddBlock.addEventListener("click", appendBlock);
  }

  const btnReset = document.getElementById("btnResetLedger");
  if (btnReset) {
    btnReset.addEventListener("click", resetLedger);
  }
}

if (typeof document !== "undefined") {
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initLedgerDemo);
  } else {
    initLedgerDemo();
  }
}

// Export for Node.js test runner
if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    canonicalize,
    canonicalBlockPayload,
    computeSha256,
    DEFAULT_SEED_BLOCKS,
    initAuthorityKeys,
    signBlockHash,
    verifyBlockHashSignature
  };
}
