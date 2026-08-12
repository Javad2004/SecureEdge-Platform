'use strict';

(() => {
  const storageKey = 'securityedge.ui.theme';
  const supportedThemes = new Set(['light', 'dark']);
  const root = document.documentElement;
  const systemPreference = window.matchMedia ? window.matchMedia('(prefers-color-scheme: dark)') : null;
  let hasUserPreference = false;
  let currentTheme = 'dark';

  function normalizeTheme(value) {
    const normalized = String(value || '').toLowerCase();
    return supportedThemes.has(normalized) ? normalized : '';
  }

  function readStoredTheme() {
    try { return normalizeTheme(localStorage.getItem(storageKey)); }
    catch { return ''; }
  }

  function writeStoredTheme(theme) {
    try {
      localStorage.setItem(storageKey, theme);
      return true;
    } catch {
      return false;
    }
  }

  function removeStoredTheme() {
    try { localStorage.removeItem(storageKey); }
    catch {}
  }

  function systemTheme() {
    return systemPreference?.matches ? 'dark' : 'light';
  }

  function themeColor(theme) {
    return theme === 'light' ? '#f4f7fb' : '#0b1020';
  }

  function updateToggleLabels() {
    const nextTheme = currentTheme === 'dark' ? 'light' : 'dark';
    const label = `Switch to ${nextTheme} mode`;
    document.querySelectorAll('[data-theme-toggle]').forEach(button => {
      button.setAttribute('aria-label', label);
      button.setAttribute('title', label);
      button.dataset.activeTheme = currentTheme;
      const text = button.querySelector('.theme-toggle-label');
      if (text) text.textContent = label;
    });
  }

  function updateThemeColorMeta() {
    const meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.setAttribute('content', themeColor(currentTheme));
  }

  function dispatchThemeChange(source) {
    window.dispatchEvent(new CustomEvent('securityedge:themechange', {
      detail: {theme: currentTheme, source}
    }));
  }

  function applyTheme(theme, {persist = false, source = 'api', announce = true} = {}) {
    const normalized = normalizeTheme(theme) || systemTheme();
    const changed = normalized !== currentTheme || root.dataset.theme !== normalized;
    currentTheme = normalized;
    root.dataset.theme = normalized;

    if (persist) {
      hasUserPreference = true;
      writeStoredTheme(normalized);
    }

    updateThemeColorMeta();
    updateToggleLabels();
    if (changed && announce) dispatchThemeChange(source);
    return normalized;
  }

  function toggleTheme() {
    return applyTheme(currentTheme === 'dark' ? 'light' : 'dark', {
      persist: true,
      source: 'user'
    });
  }

  function bindToggleButtons() {
    document.querySelectorAll('[data-theme-toggle]').forEach(button => {
      if (button.dataset.themeBound === 'true') return;
      button.dataset.themeBound = 'true';
      button.addEventListener('click', toggleTheme);
    });
    updateToggleLabels();
  }

  const storedTheme = readStoredTheme();
  if (storedTheme) {
    hasUserPreference = true;
    currentTheme = storedTheme;
  } else {
    currentTheme = systemTheme();
    removeStoredTheme();
  }

  // Apply before the stylesheet is requested so the first paint already uses
  // the correct system or persisted theme and does not flash the opposite mode.
  root.dataset.theme = currentTheme;
  updateThemeColorMeta();

  const onSystemPreferenceChange = event => {
    if (hasUserPreference) return;
    applyTheme(event.matches ? 'dark' : 'light', {source: 'system'});
  };
  if (systemPreference?.addEventListener) systemPreference.addEventListener('change', onSystemPreferenceChange);
  else if (systemPreference?.addListener) systemPreference.addListener(onSystemPreferenceChange);

  window.addEventListener('storage', event => {
    if (event.key !== storageKey && event.key !== null) return;
    const stored = event.key === null ? readStoredTheme() : normalizeTheme(event.newValue);
    if (stored) {
      hasUserPreference = true;
      applyTheme(stored, {source: 'storage'});
      return;
    }
    hasUserPreference = false;
    applyTheme(systemTheme(), {source: 'system'});
  });

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', bindToggleButtons, {once: true});
  } else {
    bindToggleButtons();
  }

  window.SecurityEdgeTheme = Object.freeze({
    storageKey,
    current: () => currentTheme,
    hasUserPreference: () => hasUserPreference,
    apply: theme => applyTheme(theme, {source: 'api'}),
    toggle: toggleTheme,
    bindToggles: bindToggleButtons
  });
})();
