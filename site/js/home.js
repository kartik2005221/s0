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
  nix: "curl -fsSL https://sector-zero.pages.dev/sh | bash",
  win: "irm https://sector-zero.pages.dev/ps1 | iex"
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
        el.textContent = "v3.0.0";
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
// allowed under the page's Content-Security-Policy, and more to the point an
// inline handler is script that had to be hashed into the policy by hand: one
// drifted character and the button stops working. Delegating once from
// document keeps the behaviour in this file, where the test suite can see it,
// and lets the markup carry intent as data attributes instead of code.
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
    switch (btn.dataset.action) {
      case "toggle-theme":
        toggleTheme();
        break;
      case "replay-terminal":
        // Defined by terminal.js, which may not have loaded.
        if (typeof window.restartTerminalShowcase === "function") {
          window.restartTerminalShowcase();
        }
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
  wireInteractions();
});
