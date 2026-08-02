import { describe, expect, it, vi } from 'vitest';

import {
  initPasskeyEnrollmentUi,
  submitEnrollment,
} from '../../../assets/js/webauthn/passkey-enrollment-ui.js';

function createFakeForm({ name = 'Work laptop' } = {}) {
  const errorNodes = [];
  const document = {
    createElement: () => {
      const node = {
        _attrs: {},
        setAttribute(name, value) {
          this._attrs[name] = value;
        },
        textContent: '',
      };
      errorNodes.push(node);
      return node;
    },
  };

  const nameInput = { value: name };
  const form = {
    ownerDocument: document,
    _children: [],
    querySelector(selector) {
      if (selector === '#passkey-name') {
        return nameInput;
      }

      if (selector === '[data-passkey-enrollment-error]') {
        return (
          this._children.find(
            (child) =>
              child._attrs?.['data-passkey-enrollment-error'] !== undefined,
          ) ?? null
        );
      }

      return null;
    },
    appendChild(node) {
      this._children.push(node);
    },
  };

  return { form, errorNodes };
}

describe('Passkey enrollment UI wiring', () => {
  it('does nothing when the enrollment form is missing', () => {
    const document = { getElementById: () => null };
    const handler = initPasskeyEnrollmentUi(document, {
      fetchImpl: vi.fn(),
    });

    expect(handler).toBeNull();
  });

  it('registers a submit handler when the form exists', () => {
    const addEventListener = vi.fn();
    const document = {
      getElementById: () => ({ addEventListener }),
    };

    initPasskeyEnrollmentUi(document, { fetchImpl: vi.fn() });

    expect(addEventListener).toHaveBeenCalledWith(
      'submit',
      expect.any(Function),
    );
  });

  it('reloads the page after a successful enrollment ceremony', async () => {
    const { form } = createFakeForm({ name: 'Work laptop' });
    const fetchImpl = vi
      .fn()
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({ publicKey: { challenge: 'abc' } }),
      })
      .mockResolvedValueOnce({ ok: true });
    const createCredential = vi.fn().mockResolvedValue({ id: 'credential-id' });
    const reload = vi.fn();

    await submitEnrollment(form, {
      fetchImpl,
      createCredential,
      reload,
      globalObject: {},
    });

    expect(fetchImpl).toHaveBeenNthCalledWith(
      1,
      '/account/security/passkeys/enroll/challenge',
      expect.objectContaining({ method: 'POST' }),
    );
    expect(createCredential).toHaveBeenCalledOnce();
    const verifyCall = fetchImpl.mock.calls[1];
    expect(verifyCall[0]).toBe('/account/security/passkeys/enroll/verify');
    expect(JSON.parse(verifyCall[1].body)).toEqual({
      credential: { id: 'credential-id' },
      name: 'Work laptop',
    });
    expect(reload).toHaveBeenCalledOnce();
  });

  it('shows an error and skips fetch when the name is blank', async () => {
    const { form } = createFakeForm({ name: '   ' });
    const fetchImpl = vi.fn();
    const createCredential = vi.fn();
    const reload = vi.fn();

    await submitEnrollment(form, {
      fetchImpl,
      createCredential,
      reload,
      globalObject: {},
    });

    expect(fetchImpl).not.toHaveBeenCalled();
    expect(reload).not.toHaveBeenCalled();
    expect(form._children[0].textContent).toBe('Passkey name is required.');
  });

  it('shows an error when the verify endpoint rejects the payload', async () => {
    const { form } = createFakeForm();
    const fetchImpl = vi
      .fn()
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({ publicKey: { challenge: 'abc' } }),
      })
      .mockResolvedValueOnce({ ok: false });
    const createCredential = vi.fn().mockResolvedValue({});
    const reload = vi.fn();

    await submitEnrollment(form, {
      fetchImpl,
      createCredential,
      reload,
      globalObject: {},
    });

    expect(reload).not.toHaveBeenCalled();
    expect(form._children[0].textContent).toBe(
      'Passkey enrollment failed. Please try again.',
    );
  });

  it('shows an error when the browser ceremony throws', async () => {
    const { form } = createFakeForm();
    const fetchImpl = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ publicKey: {} }),
    });
    const createCredential = vi
      .fn()
      .mockRejectedValue(new Error('user cancelled'));
    const reload = vi.fn();

    await submitEnrollment(form, {
      fetchImpl,
      createCredential,
      reload,
      globalObject: {},
    });

    expect(reload).not.toHaveBeenCalled();
    expect(form._children[0].textContent).toBe(
      'Passkey enrollment could not be completed.',
    );
  });
});
