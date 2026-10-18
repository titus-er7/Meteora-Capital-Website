const navToggle = document.querySelector('.nav-toggle');
const siteNav = document.querySelector('.site-nav');
const year = document.getElementById('year');
const navigationEntry = performance.getEntriesByType('navigation')[0];

if (navigationEntry?.type === 'reload') {
  history.scrollRestoration = 'manual';
  window.addEventListener('pageshow', () => {
    if (window.location.hash) {
      history.replaceState(null, '', `${window.location.pathname}${window.location.search}`);
    }

    window.scrollTo({ top: 0, left: 0, behavior: 'instant' });
  }, { once: true });
}

if (year) {
  year.textContent = new Date().getFullYear();
}

if (navToggle && siteNav) {
  navToggle.addEventListener('click', () => {
    const isOpen = siteNav.classList.toggle('is-open');
    navToggle.setAttribute('aria-expanded', String(isOpen));
  });

  siteNav.querySelectorAll('a').forEach((link) => {
    link.addEventListener('click', () => {
      siteNav.classList.remove('is-open');
      navToggle.setAttribute('aria-expanded', 'false');
    });
  });
}

const siteHeader = document.querySelector('.site-header');

if (siteHeader) {
  // The bar stays visible for the first stretch of scrolling, then slides away
  // and only returns once the page is scrolled back near the top.
  const hideAfter = 400;

  const updateHeader = () => {
    const menuOpen = siteNav?.classList.contains('is-open');
    siteHeader.classList.toggle('is-hidden', window.scrollY > hideAfter && !menuOpen);
  };

  window.addEventListener('scroll', updateHeader, { passive: true });
  updateHeader();
}

// "Back to top" goes to the very top of the page (above the header), not to
// the #top anchor on <main>, which sits below the header.
document.querySelectorAll('.footer-top-link').forEach((link) => {
  link.addEventListener('click', (event) => {
    event.preventDefault();
    window.scrollTo({ top: 0, behavior: 'smooth' });
  });
});

// Team placards: clicking one opens its bio dialog; the close button, Esc, or
// a click on the backdrop closes it.
document.querySelectorAll('.bio-trigger').forEach((trigger) => {
  const dialog = document.getElementById(trigger.getAttribute('aria-controls'));
  if (!dialog) return;

  trigger.addEventListener('click', () => {
    dialog.showModal();
    dialog.focus();
  });
  dialog.querySelector('.bio-close')?.addEventListener('click', () => dialog.close());
  dialog.addEventListener('click', (event) => {
    if (event.target === dialog) dialog.close();
  });
});
