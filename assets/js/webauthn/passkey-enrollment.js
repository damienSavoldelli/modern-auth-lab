import { arrayBufferToBase64Url, base64UrlToArrayBuffer } from './encoding.js';

export function isWebAuthnAvailable(globalObject = globalThis) {
  return (
    typeof globalObject.PublicKeyCredential !== 'undefined' &&
    typeof globalObject.navigator?.credentials?.create === 'function'
  );
}

export async function createPasskeyCredential(
  publicKeyOptions,
  globalObject = globalThis,
) {
  if (!isWebAuthnAvailable(globalObject)) {
    throw new Error('WebAuthn is not available in this browser context.');
  }

  const credential = await globalObject.navigator.credentials.create({
    publicKey: normalizeCreationOptions(publicKeyOptions),
  });

  if (!(credential instanceof globalObject.PublicKeyCredential)) {
    throw new Error('Browser did not return a public-key credential.');
  }

  return serializeCreationCredential(credential);
}

export function normalizeCreationOptions(options) {
  return {
    ...options,
    challenge: base64UrlToArrayBuffer(options.challenge),
    user: {
      ...options.user,
      id: base64UrlToArrayBuffer(options.user.id),
    },
    excludeCredentials: options.excludeCredentials.map((credential) => ({
      ...credential,
      id: base64UrlToArrayBuffer(credential.id),
    })),
  };
}

export function serializeCreationCredential(credential) {
  return {
    id: credential.id,
    rawId: arrayBufferToBase64Url(credential.rawId),
    type: credential.type,
    response: {
      attestationObject: arrayBufferToBase64Url(
        credential.response.attestationObject,
      ),
      clientDataJSON: arrayBufferToBase64Url(
        credential.response.clientDataJSON,
      ),
    },
    clientExtensionResults: credential.getClientExtensionResults(),
    transports:
      typeof credential.response.getTransports === 'function'
        ? credential.response.getTransports()
        : [],
  };
}
