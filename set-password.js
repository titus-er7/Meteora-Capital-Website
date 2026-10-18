// Set or reset an investor's password from a one-time emailed link.
(() => {
  const { session, post, takeToken, showStatus } = window.Portal;
  const $ = (id) => document.getElementById(id);
  const form = $('password-form');
  const token = takeToken();

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const password = form.password.value;
    if (password.length < 15) {
      showStatus($('password-status'), 'Use at least 15 characters.');
      return;
    }
    if (password !== form.confirm.value) {
      showStatus($('password-status'), 'The passwords do not match.');
      return;
    }
    const button = form.querySelector('button');
    button.disabled = true;
    try {
      const result = await post('/api/password/set', { token, password });
      if (!result.ok) {
        showStatus($('password-status'), result.data.error || 'Something went wrong. Please try again.');
        return;
      }
      form.reset();
      $('password-panel').hidden = true;
      $('password-done-panel').hidden = false;
    } catch {
      showStatus($('password-status'), 'Something went wrong. Please try again.');
    } finally {
      button.disabled = false;
    }
  });

  (async () => {
    if (!token) {
      showStatus($('link-status'), 'This link is invalid. Open it directly from your email.');
      return;
    }
    try {
      await session();
      $('password-panel').hidden = false;
    } catch {
      showStatus($('link-status'), 'The investor portal is temporarily unavailable.');
    }
  })();
})();
