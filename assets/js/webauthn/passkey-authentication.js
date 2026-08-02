import { arrayBufferToBase64Url, base64UrlToArrayBuffer } from './encoding.js';

export function isWebAuthnAuthenticationAvailable(globalObject = globalThis) {
  return (
    typeof globalObject.PublicKeyCredential !== 'undefined' &&
    typeof globalObject.navigator?.credentials?.get === 'function'
  );
}

export async function getPasskeyAssertion(
  publicKeyOptions,
  globalObject = globalThis,
) {
  if (!isWebAuthnAuthenticationAvailable(globalObject)) {
    throw new Error('WebAuthn is not available in this browser context.');
  }

  const credential = await globalObject.navigator.credentials.get({
    publicKey: normalizeAuthenticationOptions(publicKeyOptions),
  });

  if (!(credential instanceof globalObject.PublicKeyCredential)) {
    throw new Error('Browser did not return a public-key credential.');
  }

  return serializeAssertionCredential(credential);
}

export function normalizeAuthenticationOptions(options) {
  return {
    ...options,
    challenge: base64UrlToArrayBuffer(options.challenge),
    allowCredentials: (options.allowCredentials ?? []).map((credential) => ({
      ...credential,
      id: base64UrlToArrayBuffer(credential.id),
    })),
  };
}

export function serializeAssertionCredential(credential) {
  return {
    id: credential.id,
    rawId: arrayBufferToBase64Url(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: arrayBufferToBase64Url(
        credential.response.clientDataJSON,
      ),
      authenticatorData: arrayBufferToBase64Url(
        credential.response.authenticatorData,
      ),
      signature: arrayBufferToBase64Url(credential.response.signature),
      userHandle:
        credential.response.userHandle instanceof ArrayBuffer
          ? arrayBufferToBase64Url(credential.response.userHandle)
          : null,
    },
    clientExtensionResults:
      typeof credential.getClientExtensionResults === 'function'
        ? credential.getClientExtensionResults()
        : {},
  };
}
