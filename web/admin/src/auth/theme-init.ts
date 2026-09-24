function applyStoredTheme(): void {
  try {
    const storedTheme = window.localStorage.getItem('aegis-admin-theme');
    document.documentElement.dataset.theme = storedTheme === 'light' ? 'light' : 'dark';
  } catch {
    document.documentElement.dataset.theme = 'dark';
  }
}

applyStoredTheme();
