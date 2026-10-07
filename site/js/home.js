// Theme Management
function getPreferredTheme() {
  const stored = localStorage.getItem("s0_theme");
  if (stored) return stored;
  return window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
}

function updateFavicon(theme) {
  const iconPath = theme === "light"
    ? "assets/favicons/s0-light/favicon-32x32.png"
    : "assets/favicons/s0-dark/favicon-32x32.png";
  
  const dynamicFavicon = document.getElementById("dynamic-favicon");
  if (dynamicFavicon) {
    dynamicFavicon.href = iconPath;
  }
  const headerLogo = document.getElementById("headerLogo");
  if (headerLogo) {
    headerLogo.src = iconPath;
  }
  const footerLogo = document.getElementById("footerLogo");
  if (footerLogo) {
    footerLogo.src = iconPath;
  }
}

function applyTheme(theme) {
  document.documentElement.setAttribute("data-theme", theme);
  localStorage.setItem("s0_theme", theme);
  const label = document.getElementById("themeToggleLabel");
  if (label) {
    label.textContent = theme === "light" ? "Dark" : "Light";
  }
  updateFavicon(theme);
}

function toggleTheme() {
  const current = document.documentElement.getAttribute("data-theme") || "dark";
  const target = current === "dark" ? "light" : "dark";
  applyTheme(target);
}

// Clipboard Copy Utility
function copyText(elementId, btn) {
  const el = document.getElementById(elementId);
  if (!el) return;
  const text = el.innerText || el.textContent;

  navigator.clipboard.writeText(text.trim()).then(() => {
    const originalText = btn.textContent;
    btn.textContent = "Copied!";
    btn.classList.add("copied");
    setTimeout(() => {
      btn.textContent = originalText;
      btn.classList.remove("copied");
    }, 2000);
  }).catch(() => {
    const textArea = document.createElement("textarea");
    textArea.value = text.trim();
    document.body.appendChild(textArea);
    textArea.select();
    document.execCommand("copy");
    document.body.removeChild(textArea);
    btn.textContent = "Copied!";
    btn.classList.add("copied");
    setTimeout(() => {
      btn.textContent = "Copy";
      btn.classList.remove("copied");
    }, 2000);
  });
}

// Platform Detection and Switching for Hero Command
const PLATFORM_COMMANDS = {
  nix: "curl -fsSL https://sector0.pages.dev/sh | bash",
  win: "irm https://sector0.pages.dev/ps1 | iex"
};

function setHeroPlatform(platform) {
  const cmdSpan = document.getElementById("hero-quick-cmd");
  const nixBtn = document.getElementById("heroPlatformNix");
  const winBtn = document.getElementById("heroPlatformWin");

  if (!cmdSpan) return;
  cmdSpan.textContent = PLATFORM_COMMANDS[platform] || PLATFORM_COMMANDS.nix;

  if (nixBtn && winBtn) {
    if (platform === "win") {
      winBtn.classList.add("active");
      nixBtn.classList.remove("active");
    } else {
      nixBtn.classList.add("active");
      winBtn.classList.remove("active");
    }
  }
}

function detectPlatform() {
  const ua = navigator.userAgent || "";
  const platform = navigator.platform || "";
  if (/win/i.test(ua) || /win/i.test(platform)) {
    setHeroPlatform("win");
  } else {
    setHeroPlatform("nix");
  }
}

// Fetch Latest Release Version dynamically from GitHub API
function fetchLatestReleaseVersion() {
  const versionTags = document.querySelectorAll(".s0-release-version");
  if (!versionTags.length) return;

  fetch("https://api.github.com/repos/kartik2005221/s0/releases/latest")
    .then((res) => {
      if (!res.ok) throw new Error("Network error");
      return res.json();
    })
    .then((data) => {
      if (data && data.tag_name) {
        versionTags.forEach((el) => {
          el.textContent = data.tag_name;
        });
      }
    })
    .catch(() => {
      versionTags.forEach((el) => {
        el.textContent = "v3.1.0";
      });
    });
}

// Scroll Reveal Effect (IntersectionObserver)
function initScrollReveal() {
  const elements = document.querySelectorAll(".reveal-on-scroll");
  if (!elements.length) return;

  if ("IntersectionObserver" in window) {
    const observer = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          entry.target.classList.add("revealed");
          observer.unobserve(entry.target);
        }
      });
    }, {
      threshold: 0.12,
      rootMargin: "0px 0px -40px 0px"
    });

    elements.forEach(el => observer.observe(el));
  } else {
    elements.forEach(el => el.classList.add("revealed"));
  }
}

// Initialization
// Interaction wiring.
//
// Every control used to carry an inline onclick attribute. Those cannot be
// Header Scroll Progress
function initScrollProgress() {
  const progressBar = document.getElementById("scrollProgress");
  if (!progressBar) return;

  window.addEventListener("scroll", () => {
    const winScroll = document.documentElement.scrollTop || document.body.scrollTop;
    const height = document.documentElement.scrollHeight - document.documentElement.clientHeight;
    const scrolled = height > 0 ? (winScroll / height) * 100 : 0;
    progressBar.style.width = `${scrolled}%`;
  }, { passive: true });
}

// Chain of Custody Story
const STORY_STAGES = [
  {
    badge: "PHASE 01 · MEDIA SANITIZATION",
    cmd: "s0 wipe /dev/nvme0n1 --method crypto-erase --verify 100",
    title: "Hardware-Level Media Sanitization",
    desc: "Executes cryptographic NVMe Sanitize or multi-pass CSPRNG overwrite aligned with NIST SP 800-88 Rev. 2. Automatically verifies zero residual Shannon entropy across sample sectors and signs an Ed25519 erasure certificate.",
    standard: "NIST SP 800-88 Rev. 2 & IEEE 2883-2022",
    artifact: "Ed25519 Erasure Certificate (JSON + PDF)",
    invariant: "Zero residual data entropy (measured 0.000 bits/byte)"
  },
  {
    badge: "PHASE 02 · BIT-STREAM ACQUISITION",
    cmd: "s0 image /dev/sdb /mnt/evidence/drive.raw --dual-hash --zero-fill",
    title: "Forensic Bit-Stream Acquisition & Drive Cloning",
    desc: "Acquires raw byte-for-byte disk images with real-time streaming SHA-256 and MD5 hashing per ISO/IEC 27037. Resilient ddrescue-style bad sector zero-filling guarantees imaging never aborts mid-stream.",
    standard: "ISO/IEC 27037 Forensic Digital Evidence Handling",
    artifact: "Acquisition Manifest with Dual Hash Signatures",
    invariant: "Bit-stream identical source/image verification hash"
  },
  {
    badge: "PHASE 03 · EVIDENCE RECOVERY",
    cmd: "s0 carve /mnt/evidence/drive.raw --output /mnt/evidence/carved/ --min-confidence 0.85",
    title: "Deleted File & Artifact Carving",
    desc: "Recovers fragmented deleted documents, databases, media, and encryption keys across ext4, NTFS, FAT32, and exFAT images. Validates structural authenticity with 4-factor Shannon entropy scoring.",
    standard: "Mathematical File Structure & Cluster Bifragmentation",
    artifact: "Recovery Manifest with Extracted File Hashes",
    invariant: "Entropy confidence scoring >= threshold"
  },
  {
    badge: "PHASE 04 · AUDIT LOGGING",
    cmd: "s0 audit verify ~/.s0/s0_audit.db",
    title: "Append-Only Hash-Chained Audit Ledger",
    desc: "Every laboratory operation, drive serial number, operator identity, and crypto attestation is written to an append-only SQLite ledger chained by SHA-256 block hashes for instant tamper detection.",
    standard: "Cryptographic Tamper-Evident Ledger Integrity",
    artifact: "Audit Chain Ledger with Genesis Verification",
    invariant: "Zero broken backward-hash pointers across all records"
  },
  {
    badge: "PHASE 05 · NON-REPUDIATION VERIFICATION",
    cmd: "s0 verify cert_20261007_001.json",
    title: "Independent Mathematical Verification",
    desc: "Verifies Ed25519 signatures against pinned public authority keys with pure WebCrypto (in-browser or CLI). Canonical JSON (RFC 8785) formatting prevents semantic whitespace or encoding malleability.",
    standard: "RFC 8032 Ed25519 & RFC 8785 Canonical JSON (JCS)",
    artifact: "Cryptographic Verification Verdict (Valid / Tampered)",
    invariant: "Mathematical non-repudiation; offline proof"
  }
];

function setStoryStep(stepIndex) {
  const step = STORY_STAGES[stepIndex];
  if (!step) return;

  const badgeEl = document.getElementById("storyBadge");
  const cmdEl = document.getElementById("storyCmd");
  const titleEl = document.getElementById("storyTitle");
  const descEl = document.getElementById("storyDesc");
  const stdEl = document.getElementById("storySpecStandard");
  const artEl = document.getElementById("storySpecArtifact");
  const invEl = document.getElementById("storySpecInvariant");

  if (badgeEl) badgeEl.textContent = step.badge;
  if (cmdEl) cmdEl.textContent = step.cmd;
  if (titleEl) titleEl.textContent = step.title;
  if (descEl) descEl.textContent = step.desc;
  if (stdEl) stdEl.innerHTML = step.standard;
  if (artEl) artEl.textContent = step.artifact;
  if (invEl) invEl.textContent = step.invariant;

  document.querySelectorAll(".story-step-btn").forEach((btn, idx) => {
    const isActive = idx === Number(stepIndex);
    btn.classList.toggle("active", isActive);
    btn.setAttribute("aria-selected", isActive ? "true" : "false");
  });
}

// Live WebCrypto Hash-Chain Tamper Demo
async function computeSha256(text) {
  if (window.crypto && window.crypto.subtle) {
    const enc = new TextEncoder();
    const data = enc.encode(text);
    const hashBuf = await window.crypto.subtle.digest("SHA-256", data);
    const hashArr = Array.from(new Uint8Array(hashBuf));
    return hashArr.map(b => b.toString(16).padStart(2, "0")).join("");
  }
  let hash = 0;
  for (let i = 0; i < text.length; i++) {
    hash = ((hash << 5) - hash) + text.charCodeAt(i);
    hash |= 0;
  }
  return "hash_" + Math.abs(hash).toString(16).padStart(16, "0") + "mock000000000000000000000000000000000000000000000000";
}

async function updateHashChain(isTampered = false) {
  const genesisPrev = "0000000000000000000000000000000000000000000000000000000000000000";
  const action0 = "LAB_INITIALIZED";
  const hash0 = await computeSha256(`index=0,prev=${genesisPrev},action=${action0}`);

  const action1 = isTampered ? "MALICIOUS_ERASURE_SUPPRESSED" : "MEDIA_SANITY_PURGE";
  const hash1 = await computeSha256(`index=1,prev=${hash0},action=${action1}`);

  const legitimateHash1 = isTampered 
    ? await computeSha256(`index=1,prev=${hash0},action=MEDIA_SANITY_PURGE`)
    : hash1;
  const action2 = "BITSTREAM_ACQUISITION";
  const hash2 = await computeSha256(`index=2,prev=${legitimateHash1},action=${action2}`);

  const elAction1 = document.getElementById("blockAction1");
  const elHash0 = document.getElementById("blockHash0");
  const elPrev1 = document.getElementById("blockPrevHash1");
  const elHash1 = document.getElementById("blockHash1");
  const elPrev2 = document.getElementById("blockPrevHash2");
  const elHash2 = document.getElementById("blockHash2");

  if (elAction1) elAction1.textContent = action1;
  if (elHash0) elHash0.textContent = hash0;
  if (elPrev1) elPrev1.textContent = hash0;
  if (elHash1) elHash1.textContent = hash1;
  if (elPrev2) elPrev2.textContent = legitimateHash1;
  if (elHash2) elHash2.textContent = hash2;

  const dot = document.getElementById("chainStatusDot");
  const bannerText = document.getElementById("chainStatusText");
  const card1 = document.getElementById("blockCard1");
  const status1 = document.getElementById("blockStatus1");
  const card2 = document.getElementById("blockCard2");
  const status2 = document.getElementById("blockStatus2");
  const conn12 = document.getElementById("connector1_2");

  if (isTampered) {
    if (dot) dot.classList.add("danger");
    if (bannerText) bannerText.textContent = "Tamper Detected: Block #2 prev_hash mismatches Block #1 recomputed hash!";
    if (card1) card1.classList.add("tampered");
    if (status1) {
      status1.textContent = "TAMPERED";
      status1.className = "block-status danger";
    }
    if (card2) card2.classList.add("tampered");
    if (status2) {
      status2.textContent = "BROKEN";
      status2.className = "block-status danger";
    }
    if (conn12) {
      conn12.textContent = "≠ [BREAK]";
      conn12.classList.add("broken");
    }
  } else {
    if (dot) dot.classList.remove("danger");
    if (bannerText) bannerText.textContent = "Chain Intact: 3 of 3 blocks cryptographically valid.";
    if (card1) card1.classList.remove("tampered");
    if (status1) {
      status1.textContent = "VALID";
      status1.className = "block-status ok";
    }
    if (card2) card2.classList.remove("tampered");
    if (status2) {
      status2.textContent = "VALID";
      status2.className = "block-status ok";
    }
    if (conn12) {
      conn12.textContent = "→";
      conn12.classList.remove("broken");
    }
  }
}

// Interaction wiring
function wireInteractions() {
  document.addEventListener("click", (event) => {
    const btn = event.target.closest("button");
    if (!btn) return;

    if (btn.dataset.copyTarget) {
      copyText(btn.dataset.copyTarget, btn);
      return;
    }
    if (btn.dataset.platform) {
      setHeroPlatform(btn.dataset.platform);
      return;
    }
    if (btn.dataset.storyStep !== undefined) {
      setStoryStep(Number(btn.dataset.storyStep));
      return;
    }
    switch (btn.dataset.action) {
      case "toggle-theme":
        toggleTheme();
        break;
      case "replay-terminal":
        if (typeof window.restartTerminalShowcase === "function") {
          window.restartTerminalShowcase();
        }
        break;
      case "tamper-chain":
        updateHashChain(true);
        break;
      case "reset-chain":
        updateHashChain(false);
        break;
      default:
        break;
    }
  });
}

document.addEventListener("DOMContentLoaded", () => {
  const initialTheme = getPreferredTheme();
  applyTheme(initialTheme);
  detectPlatform();
  fetchLatestReleaseVersion();
  initScrollReveal();
  initScrollProgress();
  updateHashChain(false);
  wireInteractions();
});
