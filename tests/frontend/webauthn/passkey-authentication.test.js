import { describe, expect, it, vi } from 'vitest';

import {
  getPasskeyAssertion,
  isWebAuthnAuthenticationAvailable,
  normalizeAuthenticationOptions,
  serializeAssertionCredential,
} from '../../../assets/js/webauthn/passkey-authentication.js';

class FakePublicKeyCredential {}

describe('Passkey authentication browser module', () => {
  it('detects WebAuthn authentication availability', () => {
    expect(
      isWebAuthnAuthenticationAvailable({
        PublicKeyCredential: FakePublicKeyCredential,
        navigator: { credentials: { get: vi.fn() } },
      }),
    ).toBe(true);

    expect(
      isWebAuthnAuthenticationAvailable({
        navigator: { credentials: {} },
      }),
    ).toBe(false);
  });

  it('normalizes authentication options for navigator.credentials.get', () => {
    const normalized = normalizeAuthenticationOptions({
      challenge: '-_8A',
      allowCredentials: [
        { id: 'ZXhpc3Rpbmc', type: 'public-key', transports: ['internal'] },
      ],
    });

    expect([...new Uint8Array(normalized.challenge)]).toEqual([251, 255, 0]);
    expect(new TextDecoder().decode(normalized.allowCredentials[0].id)).toBe(
      'existing',
    );
  });

  it('handles missing allowCredentials without crashing', () => {
    const normalized = normalizeAuthenticationOptions({ challenge: 'AQ' });

    expect(normalized.allowCredentials).toEqual([]);
  });

  it('serializes an assertion credential for JSON submission', () => {
    const credential = new FakePublicKeyCredential();
    credential.id = 'credential-id';
    credential.rawId = new Uint8Array([1, 2]).buffer;
    credential.type = 'public-key';
    credential.response = {
      clientDataJSON: new Uint8Array([3]).buffer,
      authenticatorData: new Uint8Array([4]).buffer,
      signature: new Uint8Array([5]).buffer,
      userHandle: new Uint8Array([6]).buffer,
    };
    credential.getClientExtensionResults = () => ({ ext: true });

    expect(serializeAssertionCredential(credential)).toEqual({
      id: 'credential-id',
      rawId: 'AQI',
      type: 'public-key',
      response: {
        clientDataJSON: 'Aw',
        authenticatorData: 'BA',
        signature: 'BQ',
        userHandle: 'Bg',
      },
      clientExtensionResults: { ext: true },
    });
  });

  it('serializes an assertion credential without user handle', () => {
    const credential = new FakePublicKeyCredential();
    credential.id = 'credential-id';
    credential.rawId = new Uint8Array([1]).buffer;
    credential.type = 'public-key';
    credential.response = {
      clientDataJSON: new Uint8Array([2]).buffer,
      authenticatorData: new Uint8Array([3]).buffer,
      signature: new Uint8Array([4]).buffer,
      userHandle: null,
    };

    expect(
      serializeAssertionCredential(credential).response.userHandle,
    ).toBeNull();
  });

  it('calls navigator.credentials.get and serializes the result', async () => {
    const credential = new FakePublicKeyCredential();
    credential.id = 'credential-id';
    credential.rawId = new Uint8Array([1]).buffer;
    credential.type = 'public-key';
    credential.response = {
      clientDataJSON: new Uint8Array([2]).buffer,
      authenticatorData: new Uint8Array([3]).buffer,
      signature: new Uint8Array([4]).buffer,
      userHandle: null,
    };
    credential.getClientExtensionResults = () => ({});

    const get = vi.fn().mockResolvedValue(credential);
    const result = await getPasskeyAssertion(
      { challenge: 'AQ', allowCredentials: [] },
      {
        PublicKeyCredential: FakePublicKeyCredential,
        navigator: { credentials: { get } },
      },
    );

    expect(get).toHaveBeenCalledOnce();
    expect(result.id).toBe('credential-id');
    expect(result.response.signature).toBe('BA');
  });

  it('fails when WebAuthn is unavailable', async () => {
    await expect(getPasskeyAssertion({}, {})).rejects.toThrow(
      'WebAuthn is not available',
    );
  });
});
