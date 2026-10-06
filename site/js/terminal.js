// Animated Terminal Showcase Engine for s0
(function () {
  const terminalBody = document.getElementById("terminalBody");
  if (!terminalBody) return;

  const scenarios = [
    // 1. One-Line Installation
    {
      command: "curl -fsSL https://sector0.pages.dev/sh | bash",
      postCommandDelay: 500,
      outputs: [
        { text: "[1/6] Checking prerequisites... ✓ done", delay: 450, cls: "term-dim" },
        { text: "[2/6] Deploying S0 to /home/analyst/.s0... ✓ done", delay: 500, cls: "term-dim" },
        { text: "[3/6] Configuring Python virtual environment... ✓ done", delay: 550, cls: "term-dim" },
        { text: "[4/6] Upgrading pip and package managers... ✓ done", delay: 480, cls: "term-dim" },
        { text: "[5/6] Installing S0 packages and cryptographic modules... ✓ done", delay: 600, cls: "term-dim" },
        { text: "[6/6] Installing s0 command into user bin... ✓ done", delay: 420, cls: "term-dim" },
        { text: "      symlink: /home/analyst/.local/bin/s0 → /home/analyst/.s0/.venv/bin/s0", delay: 350, cls: "term-dim" },
        { text: "✓ S0 installed successfully! Ready to use.", delay: 500, cls: "term-green" }
      ],
      pauseAfter: 2000
    },

    // 2. Hardware Storage Enumeration
    {
      command: "s0 list",
      postCommandDelay: 450,
      outputs: [
        { text: "PATH           TYPE    STORAGE   CAPACITY  MODEL               MOUNTED?  OS_DRIVE?", delay: 380, cls: "term-dim" },
        { text: "/dev/nvme0n1   block   NVMe       1.0 TB   Samsung SSD 980     YES       YES [OS]", delay: 340 },
        { text: "/dev/sda       block   SATA       2.0 TB   WDC WD20EZAZ        NO        -", delay: 340 },
        { text: "/dev/sdb       block   USB       32.0 GB   SanDisk Ultra       NO        - [TARGET READY]", delay: 380, cls: "term-cyan" }
      ],
      pauseAfter: 2200
    },

    // 3. Offensive Evidence Carving / Deleted Artifact Recovery
    {
      command: "s0 carve --target /dev/sdb --out-dir /cases/evidence_01 --operator \"analyst-01\"",
      postCommandDelay: 500,
      outputs: [
        { text: "==> S0 Module 2: Advanced Forensic Evidence Carving & Reconstruction", delay: 400, cls: "term-orange" },
        { text: "Target Media   : /dev/sdb (32.0 GiB, unallocated file system sectors)", delay: 320 },
        { text: "Carving Modes  : Inode allocation table + MFT runlist + Shannon entropy evaluation", delay: 350 },
        {
          type: "progress",
          operation: "s0 carve",
          unit: "GiB",
          total: 32.0,
          speedUnit: "MB/s",
          extraField: "Found",
          stages: [
            { pct: 0,   val: " 0.0", speed: "  0", extra: " 0", eta: "--", delay: 350 },
            { pct: 22,  val: " 7.0", speed: "142", extra: " 3", eta: "3s", delay: 650 },
            { pct: 48,  val: "15.4", speed: "146", extra: " 7", eta: "2s", delay: 700 },
            { pct: 74,  val: "23.6", speed: "149", extra: "11", eta: "1s", delay: 700 },
            { pct: 92,  val: "29.4", speed: "147", extra: "14", eta: "1s", delay: 600 },
            { pct: 100, val: "32.0", speed: "146", extra: "14", eta: "0s", delay: 550 }
          ]
        },
        { text: "Bytes Scanned: 32.0 GiB | Total Files Recovered: 14", delay: 400, cls: "term-green" },
        { text: "ID             EXT        SIZE    CONF  SHA256 (PREFIX)      FILENAME", delay: 300, cls: "term-dim" },
        { text: "carve_01a9     pdf      428 KB     98%  a7f39b10c812d45e...  contract_signed.pdf", delay: 260, cls: "term-cyan" },
        { text: "carve_02b4     png      1.8 MB     95%  51b4b4e7f4934b6b...  screen_capture.png", delay: 260, cls: "term-cyan" },
        { text: "carve_03c8     docx      84 KB     91%  05dd581ce8e2041a...  financial_ledger.docx", delay: 260, cls: "term-cyan" },
        { text: "[+] Recovery Manifest: carve_manifest_e21b8a90.json (Ed25519 Signed)", delay: 320, cls: "term-green" },
        { text: "[+] Audit Ledger     : recorded block #1257 (SHA-256 Chained)", delay: 280, cls: "term-dim" }
      ],
      pauseAfter: 2400
    },

    // 4. Defensive Media Sanitization / Erasing (NIST SP 800-88 Purge)
    {
      command: "sudo s0 wipe --target /dev/sdb --yes --operator \"analyst-01\"",
      postCommandDelay: 550,
      outputs: [
        { text: "==> S0 Module 1: NIST SP 800-88 Rev. 2 Media Sanitization", delay: 400, cls: "term-orange" },
        { text: "Target Media   : /dev/sdb [SanDisk Ultra, 32.0 GiB]", delay: 320 },
        { text: "Sanitize Action: Purge (Block Erase + CSPRNG Overwrite & Verification)", delay: 350 },
        { text: "[*] Erasing drive sectors & overwriting cryptographic pattern...", delay: 450, cls: "term-dim" },
        {
          type: "progress",
          operation: "s0 wipe",
          unit: "GiB",
          total: 32.0,
          speedUnit: "MB/s",
          extraField: null,
          stages: [
            { pct: 0,   val: " 0.0", speed: "  0", eta: "--", delay: 400 },
            { pct: 11,  val: " 3.5", speed: "140", eta: "5s", delay: 650 },
            { pct: 24,  val: " 7.6", speed: "144", eta: "4s", delay: 700 },
            { pct: 38,  val: "12.1", speed: "147", eta: "3s", delay: 750 },
            { pct: 53,  val: "16.9", speed: "149", eta: "2s", delay: 800 },
            { pct: 69,  val: "22.0", speed: "151", eta: "2s", delay: 750 },
            { pct: 82,  val: "26.2", speed: "148", eta: "1s", delay: 700 },
            { pct: 94,  val: "30.0", speed: "149", eta: "1s", delay: 650 },
            { pct: 100, val: "32.0", speed: "148", eta: "0s", delay: 550 }
          ]
        },
        { text: "[*] Verifying readback: 64 random LBA clusters sampled... 0 residual bits found.", delay: 450, cls: "term-green" },
        { text: "[+] Certificate Generated: drive_wipe_certificate_a7f39b10.json (+ PDF report)", delay: 350, cls: "term-green" },
        { text: "[+] Ed25519 Signature Verified: RFC 8032 Authentic", delay: 320, cls: "term-green" },
        { text: "[+] Audit Ledger: anchored block #1258 (51b4b4e7f493...)", delay: 320, cls: "term-dim" }
      ],
      pauseAfter: 2400
    },

    // 5. Cryptographic Hash-Chained Audit Ledger Verification
    {
      command: "s0 audit verify",
      postCommandDelay: 450,
      outputs: [
        { text: "==> Auditing Hash-Chained Cryptographic Ledger (SQLite)...", delay: 380, cls: "term-dim" },
        { text: "Chain Status : ✅ VALID & CONTINUOUS", delay: 400, cls: "term-green" },
        { text: "Blocks Tested: 1,258 blocks verified", delay: 280 },
        { text: "Details      : Hash-chain unbroken. All Ed25519 signatures authentic.", delay: 320, cls: "term-cyan" }
      ],
      pauseAfter: 2200
    },

    // 6. Zero-Trust Air-Gapped Certificate Verification
    {
      command: "s0 verify drive_wipe_certificate_a7f39b10.json",
      postCommandDelay: 450,
      outputs: [
        { text: "✅ CERTIFICATE AUTHENTIC & VERIFIED", delay: 400, cls: "term-green" },
        { text: "UUID         : a7f39b10-82a1-4ef2-9381-12c84092b115", delay: 220 },
        { text: "Status       : success (Media Sanitization)", delay: 200 },
        { text: "NIST SP 800  : Purge (0 residual clusters)", delay: 200 },
        { text: "Target Media : /dev/sdb (32.0 GiB)", delay: 200 },
        { text: "Issuer       : Accredited Digital Forensics Lab Root", delay: 220, cls: "term-dim" },
        { text: "Fingerprint  : sha256:8396af8c07a7d40f98ba492cf2b61e23fa...", delay: 240, cls: "term-dim" },
        { text: "Verdict      : RFC 8785 Canonical JSON validated in 4.1ms.", delay: 300, cls: "term-cyan" }
      ],
      pauseAfter: 1200
    }
  ];

  let isRunning = false;
  let hasStarted = false;
  let abortController = null;

  function sleep(ms, signal) {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(resolve, ms);
      if (signal) {
        signal.addEventListener("abort", () => {
          clearTimeout(timer);
          reject(new Error("aborted"));
        });
      }
    });
  }

  // Smooth scroll to bottom only if user hasn't manually scrolled up to inspect earlier logs
  function autoScroll() {
    const threshold = 120;
    const isNearBottom = terminalBody.scrollHeight - terminalBody.scrollTop - terminalBody.clientHeight <= threshold;
    if (isNearBottom) {
      terminalBody.scrollTop = terminalBody.scrollHeight;
    }
  }

  async function typeCommand(lineElement, text, signal) {
    const promptSpan = document.createElement("span");
    promptSpan.className = "term-prompt";
    promptSpan.textContent = "analyst@s0:~$ ";
    lineElement.appendChild(promptSpan);

    const cmdSpan = document.createElement("span");
    cmdSpan.className = "term-cmd";
    lineElement.appendChild(cmdSpan);

    const cursor = document.createElement("span");
    cursor.className = "term-cursor";
    lineElement.appendChild(cursor);

    for (let i = 0; i < text.length; i++) {
      cmdSpan.textContent += text[i];
      autoScroll();
      // Deliberate human typing rhythm (50ms to 85ms per character)
      await sleep(50 + Math.random() * 35, signal);
    }

    await sleep(280, signal);
    cursor.remove();
  }

  // Slower, smooth animated progress bar
  async function animateProgressBar(lineElement, cfg, signal) {
    lineElement.className = "terminal-line term-cyan";
    const op = cfg.operation || "s0 task";

    for (const stage of cfg.stages) {
      const filled = Math.round((stage.pct / 100) * 20);
      const empty = 20 - filled;
      const bar = "█".repeat(filled) + "░".repeat(empty);
      const extraPart = cfg.extraField ? ` | ${cfg.extraField}: ${stage.extra}` : "";
      lineElement.textContent = `[${op}] | [${bar}] | ${String(stage.pct).padStart(3, " ")}.0% | ${stage.val} ${cfg.unit} | ${stage.speed} ${cfg.speedUnit}${extraPart} | ETA: ${stage.eta}`;
      autoScroll();
      await sleep(stage.delay, signal);
    }
  }

  async function runShowcase() {
    if (isRunning) return;
    isRunning = true;
    abortController = new AbortController();
    const signal = abortController.signal;

    try {
      terminalBody.innerHTML = "";

      // Run each scenario ONCE in sequence
      for (const scenario of scenarios) {
        const cmdLine = document.createElement("div");
        cmdLine.className = "terminal-line";
        terminalBody.appendChild(cmdLine);

        await typeCommand(cmdLine, scenario.command, signal);
        await sleep(scenario.postCommandDelay || 450, signal);

        for (const out of scenario.outputs) {
          const outLine = document.createElement("div");
          terminalBody.appendChild(outLine);

          if (out.type === "progress") {
            await animateProgressBar(outLine, out, signal);
          } else {
            outLine.className = `terminal-line ${out.cls || ""}`;
            outLine.textContent = out.text;
            autoScroll();
            await sleep(out.delay || 300, signal);
          }
        }

        const spacer = document.createElement("div");
        spacer.style.height = "12px";
        terminalBody.appendChild(spacer);
        autoScroll();

        await sleep(scenario.pauseAfter || 1800, signal);
      }

      // FINAL STATE: Stop here! Do not clear, do not repeat.
      // Append standing active prompt with blinking cursor so user can see and inspect the full history.
      const finalPromptLine = document.createElement("div");
      finalPromptLine.className = "terminal-line";
      const promptSpan = document.createElement("span");
      promptSpan.className = "term-prompt";
      promptSpan.textContent = "analyst@s0:~$ ";
      const finalCursor = document.createElement("span");
      finalCursor.className = "term-cursor";
      finalPromptLine.appendChild(promptSpan);
      finalPromptLine.appendChild(finalCursor);
      terminalBody.appendChild(finalPromptLine);
      autoScroll();

    } catch (err) {
      // Aborted cleanly on replay
    } finally {
      isRunning = false;
    }
  }

  function restartShowcase() {
    if (abortController) {
      abortController.abort();
    }
    setTimeout(() => {
      terminalBody.innerHTML = "";
      runShowcase();
    }, 120);
  }

  window.restartTerminalShowcase = restartShowcase;

  // Start live terminal demo ONLY when the user scrolls to it
  function initTerminalObserver() {
    const demoSection = document.getElementById("demo");
    if (!demoSection) return;

    if ("IntersectionObserver" in window) {
      const observer = new IntersectionObserver((entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting && !hasStarted) {
            hasStarted = true;
            setTimeout(runShowcase, 300);
            observer.unobserve(entry.target);
          }
        });
      }, {
        threshold: 0.25,
        rootMargin: "0px 0px -40px 0px"
      });

      observer.observe(demoSection);
    } else {
      setTimeout(runShowcase, 1000);
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initTerminalObserver);
  } else {
    initTerminalObserver();
  }
})();
