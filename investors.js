// Investors page: sign in, request access (accredited investor attestation),
// and, once signed in, the DocSend links. Values from the server or the user
// are only written with textContent or validated https hrefs, never as HTML.
(() => {
  const { session, get, post, showStatus } = window.Portal;
  const $ = (id) => document.getElementById(id);

  const panels = ['login-panel', 'request-panel', 'request-done-panel', 'materials-panel'];

  // Set when the portal server can't be reached (e.g. static hosting such as
  // GitHub Pages). The screens still show; submitting explains it's not live yet.
  let offline = false;
  const OFFLINE_MESSAGE = 'The investor portal is not available right now. Please contact info@meteoracapital.com.';
  const unavailable = (statusEl) => {
    if (offline) showStatus(statusEl, OFFLINE_MESSAGE);
    return offline;
  };
  const show = (id) => panels.forEach((panel) => { $(panel).hidden = panel !== id; });

  // Disable a form's buttons while its request is in flight.
  const busy = async (form, task) => {
    const buttons = form.querySelectorAll('button');
    buttons.forEach((b) => { b.disabled = true; });
    try {
      return await task();
    } catch {
      return { ok: false, data: { error: 'Something went wrong. Please try again.' } };
    } finally {
      buttons.forEach((b) => { b.disabled = false; });
    }
  };

  const safeHttpsUrl = (value) => {
    try {
      const url = new URL(value);
      return url.protocol === 'https:' ? url.href : null;
    } catch {
      return null;
    }
  };

  const showMaterials = async (name) => {
    const result = await get('/api/materials');
    if (!result.ok) {
      show('login-panel');
      return;
    }
    const { materials = {} } = result.data;
    const links = { 'material-deck': materials.deck, 'material-tearsheet': materials.tearSheet };
    Object.entries(links).forEach(([id, value]) => {
      const href = safeHttpsUrl(value);
      if (href) $(id).href = href;
      else $(id).hidden = true;
    });
    $('investor-name').textContent = name || '';
    show('materials-panel');
  };

  // --- Sign in -------------------------------------------------------------
  const loginForm = $('login-form');
  loginForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    const email = loginForm.email.value.trim();
    const password = loginForm.password.value;
    if (!email || !password) {
      showStatus($('login-status'), 'Enter your email and password.');
      return;
    }
    if (unavailable($('login-status'))) return;
    const result = await busy(loginForm, () => post('/api/login', { email, password }));
    loginForm.password.value = '';
    if (!result.ok) {
      showStatus($('login-status'), result.data.error || 'Sign in failed.');
      return;
    }
    showStatus($('login-status'), '');
    await showMaterials(result.data.name);
  });

  const forgotForm = $('forgot-form');
  $('show-forgot').addEventListener('click', () => {
    forgotForm.hidden = !forgotForm.hidden;
    if (!forgotForm.hidden) {
      forgotForm.email.value = loginForm.email.value.trim();
      forgotForm.email.focus();
    }
  });
  forgotForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    const email = forgotForm.email.value.trim();
    if (!forgotForm.email.checkValidity() || !email) {
      showStatus($('forgot-status'), 'Enter a valid email address.');
      return;
    }
    if (unavailable($('forgot-status'))) return;
    const result = await busy(forgotForm, () => post('/api/password/forgot', { email }));
    showStatus($('forgot-status'), result.data.message || result.data.error || '', result.ok ? 'success' : 'error');
  });

  $('logout').addEventListener('click', async () => {
    await post('/api/logout', {});
    show('login-panel');
  });

  // --- Request access ------------------------------------------------------
  const form = $('attestation-form');
  const investorType = () => form.querySelector('input[name="investorType"]:checked')?.value || 'individual';

  // Show the qualifications (and entity name) for the selected investor type.
  const syncInvestorType = () => {
    const type = investorType();
    form.querySelectorAll('[data-basis-for]').forEach((group) => {
      group.hidden = group.dataset.basisFor !== type;
    });
    $('entity-field').hidden = type !== 'entity';
    form.entityName.required = type === 'entity';
  };

  const collect = () => {
    const type = investorType();
    return {
      fullName: form.fullName.value.trim(),
      email: form.email.value.trim(),
      investorType: type,
      entityName: type === 'entity' ? form.entityName.value.trim() : '',
      basis: Array.from(form.querySelectorAll(`[data-basis-for="${type}"] input[name="basis"]:checked`), (box) => box.value),
      attest: form.attest.checked,
      signature: form.signature.value.trim(),
    };
  };

  // Mirrors the server's checks so most mistakes are caught before sending.
  const check = (data) => {
    if (!data.fullName) return 'Enter your full name.';
    if (!form.email.checkValidity() || !data.email) return 'Enter a valid email address.';
    if (data.investorType === 'entity' && !data.entityName) return 'Enter the entity name.';
    if (!data.basis.length) return 'Select at least one qualification.';
    if (!data.attest) return 'Confirm the attestation to continue.';
    const normalize = (value) => value.replace(/\s+/g, ' ').toLowerCase();
    if (normalize(data.signature) !== normalize(data.fullName)) return 'Your signature must match your full name.';
    return '';
  };

  form.querySelectorAll('input[name="investorType"]').forEach((radio) => {
    radio.addEventListener('change', syncInvestorType);
  });

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const data = collect();
    const problem = check(data);
    if (problem) {
      showStatus($('request-status'), problem);
      return;
    }
    if (unavailable($('request-status'))) return;
    const result = await busy(form, () => post('/api/request-access', data));
    if (!result.ok) {
      showStatus($('request-status'), result.data.error || 'Something went wrong. Please try again.');
      return;
    }
    showStatus($('request-status'), '');
    $('request-done-message').textContent = result.data.message;
    show('request-done-panel');
  });

  $('show-request').addEventListener('click', () => show('request-panel'));
  $('back-to-login').addEventListener('click', () => show('login-panel'));

  // --- Start -----------------------------------------------------------------
  syncInvestorType();
  session()
    .then((state) => (state.loggedIn ? showMaterials(state.name) : show('login-panel')))
    .catch(() => {
      offline = true;
      show('login-panel');
    });
})();
