export function createAppTitle(projectName) {
  return `${projectName} Backend and Frontend Tooling`;
}

export function renderApp(root) {
  root.innerHTML = `
    <section class="intro" aria-labelledby="page-title">
      <p class="eyebrow">Security education lab</p>
      <h1 id="page-title">${createAppTitle('Modern Auth Lab')}</h1>
      <p class="summary">
        A progressive foundation for learning password authentication, TOTP,
        Passkeys/WebAuthn, secure fallback strategies, tests, and CI/CD.
      </p>
    </section>
  `;
}

const root =
  typeof document === 'undefined'
    ? null
    : document.querySelector('[data-app-root]');

if (root !== null) {
  renderApp(root);
}
