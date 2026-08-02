export function base64UrlToArrayBuffer(value) {
  if (typeof value !== 'string' || value.length === 0) {
    throw new TypeError('Base64URL value must be a non-empty string.');
  }

  const base64 = value.replaceAll('-', '+').replaceAll('_', '/');
  const padded = base64.padEnd(
    base64.length + ((4 - (base64.length % 4)) % 4),
    '=',
  );
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);

  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }

  return bytes.buffer;
}

export function arrayBufferToBase64Url(buffer) {
  if (!(buffer instanceof ArrayBuffer)) {
    throw new TypeError('Value must be an ArrayBuffer.');
  }

  const bytes = new Uint8Array(buffer);
  let binary = '';

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary)
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replaceAll('=', '');
}
