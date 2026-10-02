function copyText(id, btn) {
  const text = document.getElementById(id).innerText;
  navigator.clipboard.writeText(text).then(() => {
    const orig = btn.innerText;
    btn.innerText = 'Copied!';
    btn.classList.add('copied');
    setTimeout(() => {
      btn.innerText = orig;
      btn.classList.remove('copied');
    }, 1800);
  });
}

function updateFavicon(theme) {
  const fav = document.getElementById('dynamic-favicon');
  if (fav) {
    fav.href = theme === 'dark' ? 'assets/favicons/s0-dark/favicon-32x32.png' : 'assets/favicons/s0-light/favicon-32x32.png';
  }
  const logo = document.getElementById('headerLogo');
  if (logo) {
    logo.src = theme === 'dark' ? 'assets/favicons/s0-dark/favicon-32x32.png' : 'assets/favicons/s0-light/favicon-32x32.png';
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

/* Interaction wiring.
 *
 * These controls used to carry inline onclick attributes. This page's policy is
 * script-src 'self' with no 'unsafe-inline' -- inline handlers need
 * 'unsafe-inline', so every one of them was blocked by the browser and the
 * copy buttons did nothing. Binding here is what makes them work at all.
 */
function wireInteractions() {
  document.addEventListener('click', function(event) {
    const btn = event.target.closest('button');
    if (!btn) return;

    if (btn.dataset.copyTarget) {
      copyText(btn.dataset.copyTarget, btn);
      return;
    }
    if (btn.dataset.action === 'toggle-theme') {
      toggleTheme();
    }
  });
}

(function() {
  const saved = localStorage.getItem('s0_theme') || 'dark';
  document.documentElement.setAttribute('data-theme', saved);
  updateThemeBtn(saved);
  updateFavicon(saved);
  wireInteractions();
})();
