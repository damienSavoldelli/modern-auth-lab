import { describe, expect, it, vi } from 'vitest';

import {
  createPasskeyCredential,
  isWebAuthnAvailable,
  normalizeCreationOptions,
  serializeCreationCredential,
} from '../../../assets/js/webauthn/passkey-enrollment.js';

class FakePublicKeyCredential {}

describe('Passkey enrollment browser module', () => {
  it('detects WebAuthn availability', () => {
    expect(
      isWebAuthnAvailable({
        PublicKeyCredential: FakePublicKeyCredential,
        navigator: {
          credentials: {
            create: vi.fn(),
          },
        },
      }),
    ).toBe(true);

    expect(isWebAuthnAvailable({ navigator: { credentials: {} } })).toBe(false);
  });

  it('normalizes creation options for navigator.credentials.create', () => {
    const normalized = normalizeCreationOptions({
      challenge: '-_8A',
      user: {
        id: 'dXNlcjox',
        name: 'user@example.com',
        displayName: 'user@example.com',
      },
      excludeCredentials: [
        {
          id: 'ZXhpc3Rpbmc',
          type: 'public-key',
          transports: ['usb'],
        },
      ],
    });

    expect([...new Uint8Array(normalized.challenge)]).toEqual([251, 255, 0]);
    expect(new TextDecoder().decode(normalized.user.id)).toBe('user:1');
    expect(new TextDecoder().decode(normalized.excludeCredentials[0].id)).toBe(
      'existing',
    );
  });

  it('serializes a created public-key credential', () => {
    const credential = new FakePublicKeyCredential();
    credential.id = 'credential-id';
    credential.rawId = new Uint8Array([1, 2, 3]).buffer;
    credential.type = 'public-key';
    credential.response = {
      attestationObject: new Uint8Array([4, 5, 6]).buffer,
      clientDataJSON: new Uint8Array([7, 8, 9]).buffer,
      getTransports: () => ['internal'],
    };
    credential.getClientExtensionResults = () => ({ credProps: { rk: true } });

    expect(serializeCreationCredential(credential)).toEqual({
      id: 'credential-id',
      rawId: 'AQID',
      type: 'public-key',
      response: {
        attestationObject: 'BAUG',
        clientDataJSON: 'BwgJ',
      },
      clientExtensionResults: { credProps: { rk: true } },
      transports: ['internal'],
    });
  });

  it('calls navigator.credentials.create and serializes the result', async () => {
    const credential = new FakePublicKeyCredential();
    credential.id = 'credential-id';
    credential.rawId = new Uint8Array([1]).buffer;
    credential.type = 'public-key';
    credential.response = {
      attestationObject: new Uint8Array([2]).buffer,
      clientDataJSON: new Uint8Array([3]).buffer,
    };
    credential.getClientExtensionResults = () => ({});

    const create = vi.fn().mockResolvedValue(credential);

    const result = await createPasskeyCredential(
      {
        challenge: 'AQ',
        user: { id: 'dXNlcjox', name: 'user@example.com' },
        excludeCredentials: [],
      },
      {
        PublicKeyCredential: FakePublicKeyCredential,
        navigator: {
          credentials: {
            create,
          },
        },
      },
    );

    expect(create).toHaveBeenCalledOnce();
    expect(result.rawId).toBe('AQ');
    expect(result.response.attestationObject).toBe('Ag');
    expect(result.response.clientDataJSON).toBe('Aw');
  });

  it('fails when WebAuthn is unavailable', async () => {
    await expect(createPasskeyCredential({}, {})).rejects.toThrow(
      'WebAuthn is not available',
    );
  });
});
