import { describe, expect, it } from 'vitest';

import {
  arrayBufferToBase64Url,
  base64UrlToArrayBuffer,
} from '../../../assets/js/webauthn/encoding.js';

describe('WebAuthn Base64URL encoding', () => {
  it('converts Base64URL text to an ArrayBuffer', () => {
    const buffer = base64UrlToArrayBuffer('-_8A');

    expect([...new Uint8Array(buffer)]).toEqual([251, 255, 0]);
  });

  it('converts an ArrayBuffer to unpadded Base64URL text', () => {
    const buffer = new Uint8Array([251, 255, 0]).buffer;

    expect(arrayBufferToBase64Url(buffer)).toBe('-_8A');
  });

  it('rejects empty Base64URL values', () => {
    expect(() => base64UrlToArrayBuffer('')).toThrow(TypeError);
  });

  it('rejects non ArrayBuffer values', () => {
    expect(() => arrayBufferToBase64Url('not-a-buffer')).toThrow(TypeError);
  });
});
