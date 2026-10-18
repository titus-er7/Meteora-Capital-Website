// Shared helpers for the investor portal pages (investors, review,
// set-password). Every POST carries the session's CSRF token.
window.Portal = (() => {
  let csrfToken = '';

  const parse = async (response) => {
    const data = await response.json().catch(() => ({}));
    if (data.csrfToken) csrfToken = data.csrfToken;
    return { ok: response.ok && data.ok !== false, status: response.status, data };
  };

  const session = async () => {
    const result = await parse(await fetch('/api/session', { credentials: 'same-origin' }));
    if (!result.ok) throw new Error('session');
    return result.data;
  };

  const get = async (url) => parse(await fetch(url, { credentials: 'same-origin' }));

  const post = async (url, body) =>
    parse(
      await fetch(url, {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
        body: JSON.stringify(body),
      }),
    );

  // One-time tokens arrive in the URL fragment (#token=...), which is never
  // sent to the server or leaked in Referer. Clear it from the address bar.
  const takeToken = () => {
    const token = new URLSearchParams(window.location.hash.slice(1)).get('token') || '';
    if (token) history.replaceState(null, '', window.location.pathname);
    return token;
  };

  const showStatus = (el, message, kind = 'error') => {
    el.textContent = message;
    el.classList.toggle('is-success', kind === 'success');
    el.hidden = !message;
  };

  return { session, get, post, takeToken, showStatus };
})();
