function copyText(id, btn) {
  const el = document.getElementById(id);
  if (!el) return;
  const text = el.innerText || el.textContent;
  navigator.clipboard.writeText(text.trim()).then(() => {
    const orig = btn.innerText;
    btn.innerText = 'Copied!';
    btn.classList.add('copied');
    const status = document.getElementById('installStatus');
    if (status) status.textContent = 'Command copied to clipboard.';
    setTimeout(() => {
      btn.innerText = orig;
      btn.classList.remove('copied');
    }, 1800);
  });
}

function updateFavicon(theme) {
  const fav = document.getElementById('dynamic-favicon');
  if (fav) {
    fav.href = theme === 'dark' ? '../assets/favicons/s0-dark/favicon-32x32.png' : '../assets/favicons/s0-light/favicon-32x32.png';
  }
  const logo = document.getElementById('headerLogo');
  if (logo) {
    logo.src = theme === 'dark' ? '../assets/favicons/s0-dark/favicon-32x32.png' : '../assets/favicons/s0-light/favicon-32x32.png';
  }
  const footerLogo = document.getElementById('footerLogo');
  if (footerLogo) {
    footerLogo.src = theme === 'dark' ? '../assets/favicons/s0-dark/favicon-32x32.png' : '../assets/favicons/s0-light/favicon-32x32.png';
  }
}

function updateThemeBtn(theme) {
  const lbl = document.getElementById('themeToggleLabel');
  if (lbl) {
    lbl.innerText = theme === 'dark' ? 'Light' : 'Dark';
  }
}

function toggleTheme() {
  const current = document.documentElement.getAttribute('data-theme') || 'dark';
  const next = current === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  localStorage.setItem('s0_theme', next);
  updateThemeBtn(next);
  updateFavicon(next);
}

function switchTab(tabId) {
  document.querySelectorAll('.tab-btn').forEach(btn => {
    const active = btn.dataset.tab === tabId;
    btn.classList.toggle('active', active);
    btn.setAttribute('aria-selected', active ? 'true' : 'false');
  });
  document.querySelectorAll('.tab-panel').forEach(panel => {
    panel.classList.toggle('active', panel.id === tabId);
  });
}

function initScrollProgress() {
  const progressBar = document.getElementById('scrollProgress');
  if (!progressBar) return;

  window.addEventListener('scroll', () => {
    const winScroll = document.documentElement.scrollTop || document.body.scrollTop;
    const height = document.documentElement.scrollHeight - document.documentElement.clientHeight;
    const scrolled = height > 0 ? (winScroll / height) * 100 : 0;
    progressBar.style.width = `${scrolled}%`;
  }, { passive: true });
}

function wireInteractions() {
  document.addEventListener('click', function(event) {
    const btn = event.target.closest('button');
    if (!btn) return;

    if (btn.dataset.copyTarget) {
      copyText(btn.dataset.copyTarget, btn);
      return;
    }
    if (btn.dataset.tab) {
      switchTab(btn.dataset.tab);
      return;
    }
    if (btn.dataset.action === 'toggle-theme') {
      toggleTheme();
    }
  });
}

(function() {
  const saved = localStorage.getItem('s0_theme') || (window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
  document.documentElement.setAttribute('data-theme', saved);
  updateThemeBtn(saved);
  updateFavicon(saved);
  initScrollProgress();
  wireInteractions();
})();
