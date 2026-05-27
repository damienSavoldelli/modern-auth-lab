import { describe, expect, it } from 'vitest';

import { createAppTitle, renderApp } from '../../assets/js/main.js';

describe('frontend entrypoint', () => {
  it('creates the app title', () => {
    expect(createAppTitle('Modern Auth Lab')).toBe(
      'Modern Auth Lab Backend and Frontend Tooling',
    );
  });

  it('renders the initial app shell content', () => {
    const root = { innerHTML: '' };

    renderApp(root);

    expect(root.innerHTML).toContain(
      'Modern Auth Lab Backend and Frontend Tooling',
    );
    expect(root.innerHTML).toContain('Security education lab');
  });
});
