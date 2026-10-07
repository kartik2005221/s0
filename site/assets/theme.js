/**
 * s0 Unified Theme Controller
 * Handles dark / light theme switching across all four surfaces.
 */
(function() {
  'use strict';

  var THEME_KEY = 's0_theme';

  function getEffectiveTheme() {
    var stored = localStorage.getItem(THEME_KEY);
    if (stored === 'light' || stored === 'dark') {
      return stored;
    }
    return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
  }

  function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    var label = document.getElementById('themeToggleLabel');
    if (label) {
      label.textContent = theme === 'dark' ? 'Light' : 'Dark';
    }
    var toggleBtn = document.getElementById('themeToggleBtn');
    if (toggleBtn) {
      toggleBtn.setAttribute('aria-label', 'Switch to ' + (theme === 'dark' ? 'light' : 'dark') + ' theme');
      toggleBtn.setAttribute('title', 'Switch to ' + (theme === 'dark' ? 'light' : 'dark') + ' theme');
    }
    // Update dynamic favicons if present
    var fav = document.getElementById('dynamic-favicon');
    if (fav) {
      fav.href = fav.href.replace(/s0-(dark|light)/, 's0-' + theme);
    }
  }

  function toggleTheme() {
    var current = document.documentElement.getAttribute('data-theme') || getEffectiveTheme();
    var next = current === 'dark' ? 'light' : 'dark';
    localStorage.setItem(THEME_KEY, next);
    applyTheme(next);
  }

  function init() {
    var theme = getEffectiveTheme();
    applyTheme(theme);

    // Watch OS preference changes when no explicit choice has been stored
    window.matchMedia('(prefers-color-scheme: light)').addEventListener('change', function(e) {
      if (!localStorage.getItem(THEME_KEY)) {
        applyTheme(e.matches ? 'light' : 'dark');
      }
    });

    // Bind theme toggle buttons
    document.addEventListener('click', function(e) {
      var target = e.target.closest('#themeToggleBtn, [data-action="toggle-theme"]');
      if (target) {
        e.preventDefault();
        toggleTheme();
      }
    });

    // Scroll progress bar
    var progressBar = document.querySelector('.header-scroll-progress');
    if (progressBar) {
      window.addEventListener('scroll', function() {
        var winScroll = document.documentElement.scrollTop || document.body.scrollTop;
        var height = document.documentElement.scrollHeight - document.documentElement.clientHeight;
        var scrolled = height > 0 ? (winScroll / height) * 100 : 0;
        progressBar.style.width = scrolled + '%';
      }, { passive: true });
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  // Export for external modules
  window.s0Theme = {
    get: getEffectiveTheme,
    set: function(theme) {
      localStorage.setItem(THEME_KEY, theme);
      applyTheme(theme);
    },
    toggle: toggleTheme
  };
})();
