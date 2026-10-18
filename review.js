// Approver review page: opened from the one-time link in the request email.
// Loading the page never changes anything; only the buttons do (so email
// link scanners that open the URL can't approve a request).
(() => {
  const { session, post, takeToken, showStatus } = window.Portal;
  const $ = (id) => document.getElementById(id);
  const statusEl = $('review-status');
  const token = takeToken();

  const fill = (request) => {
    $('r-name').textContent = request.fullName;
    $('r-email').textContent = request.email;
    $('r-type').textContent = request.investorType === 'entity' ? 'Entity' : 'Individual';
    $('r-entity').textContent = request.entityName || '-';
    $('r-signature').textContent = request.signature;
    $('r-submitted').textContent = new Date(request.submitted).toLocaleString();
    const list = $('r-quals');
    request.qualifications.forEach((text) => {
      const item = document.createElement('li');
      item.textContent = text;
      list.append(item);
    });
  };

  const decide = async (decision) => {
    const buttons = document.querySelectorAll('#review-panel button');
    buttons.forEach((b) => { b.disabled = true; });
    try {
      const result = await post('/api/review/decide', { token, decision });
      if (!result.ok) {
        showStatus(statusEl, result.data.error || 'Something went wrong. Please try again.');
        buttons.forEach((b) => { b.disabled = false; });
        return;
      }
      $('review-panel').hidden = true;
      const done = result.data.status === 'approved'
        ? 'Access approved. The investor has been emailed a link to set their password.'
        : 'Request denied. The investor has not been given access.';
      showStatus(statusEl, result.data.warning || done, result.data.warning ? 'error' : 'success');
    } catch {
      showStatus(statusEl, 'Something went wrong. Please try again.');
      buttons.forEach((b) => { b.disabled = false; });
    }
  };

  $('approve').addEventListener('click', () => decide('approve'));
  $('deny').addEventListener('click', () => {
    if (window.confirm('Deny this request?')) decide('deny');
  });

  (async () => {
    if (!token) {
      showStatus(statusEl, 'This review link is invalid. Open it directly from the request email.');
      return;
    }
    try {
      await session();
      const result = await post('/api/review/details', { token });
      if (!result.ok) {
        showStatus(statusEl, result.data.error || 'This review link is invalid, already used or expired.');
        return;
      }
      fill(result.data.request);
      $('review-panel').hidden = false;
    } catch {
      showStatus(statusEl, 'The investor portal is temporarily unavailable.');
    }
  })();
})();
