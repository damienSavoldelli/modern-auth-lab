import { describe, expect, it, vi } from 'vitest';

import {
  initPasskeyLoginUi,
  runPasskeyLogin,
} from '../../../assets/js/webauthn/passkey-login-ui.js';

function createFakeStatusNode() {
  return { textContent: '' };
}

describe('Passkey login UI wiring', () => {
  it('does nothing when the trigger is missing', () => {
    const document = { getElementById: () => null };
    const handler = initPasskeyLoginUi(document, {
      fetchImpl: vi.fn(),
    });

    expect(handler).toBeNull();
  });

  it('registers a click handler when the trigger exists', () => {
    const addEventListener = vi.fn();
    const document = {
      getElementById: (id) => {
        if (id === 'passkey-login-trigger') {
          return { addEventListener };
        }
        return createFakeStatusNode();
      },
    };

    initPasskeyLoginUi(document, { fetchImpl: vi.fn() });

    expect(addEventListener).toHaveBeenCalledWith(
      'click',
      expect.any(Function),
    );
  });

  it('navigates to the account page after a successful ceremony', async () => {
    const status = createFakeStatusNode();
    const fetchImpl = vi
      .fn()
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({ publicKey: { challenge: 'abc' } }),
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({ status: 'ok', redirect: '/account' }),
      });
    const getAssertion = vi.fn().mockResolvedValue({ id: 'credential' });
    const navigateTo = vi.fn();

    await runPasskeyLogin({
      fetchImpl,
      getAssertion,
      navigateTo,
      globalObject: {},
      status,
    });

    expect(navigateTo).toHaveBeenCalledWith('/account');
    expect(status.textContent).toBe('');
    const verifyCall = fetchImpl.mock.calls[1];
    expect(verifyCall[0]).toBe('/login/passkey/verify');
    expect(JSON.parse(verifyCall[1].body)).toEqual({
      credential: { id: 'credential' },
    });
  });

  it('shows an error when the verify endpoint rejects the payload', async () => {
    const status = createFakeStatusNode();
    const fetchImpl = vi
      .fn()
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({ publicKey: { challenge: 'abc' } }),
      })
      .mockResolvedValueOnce({ ok: false });
    const getAssertion = vi.fn().mockResolvedValue({});
    const navigateTo = vi.fn();

    await runPasskeyLogin({
      fetchImpl,
      getAssertion,
      navigateTo,
      globalObject: {},
      status,
    });

    expect(navigateTo).not.toHaveBeenCalled();
    expect(status.textContent).toBe('Passkey login failed. Please try again.');
  });

  it('shows an error when the browser ceremony throws', async () => {
    const status = createFakeStatusNode();
    const fetchImpl = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ publicKey: {} }),
    });
    const getAssertion = vi.fn().mockRejectedValue(new Error('cancelled'));
    const navigateTo = vi.fn();

    await runPasskeyLogin({
      fetchImpl,
      getAssertion,
      navigateTo,
      globalObject: {},
      status,
    });

    expect(navigateTo).not.toHaveBeenCalled();
    expect(status.textContent).toBe('Passkey login could not be completed.');
  });
});
