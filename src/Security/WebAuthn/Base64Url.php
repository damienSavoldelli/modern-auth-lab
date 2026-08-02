<?php

declare(strict_types=1);

namespace ModernAuthLab\Security\WebAuthn;

use InvalidArgumentException;

/**
 * Encodes and decodes URL-safe Base64 values used by browser WebAuthn JSON.
 *
 * WebAuthn browser APIs use binary `ArrayBuffer` values. JSON endpoints need a
 * deterministic text representation, so the project uses unpadded Base64URL.
 */
final readonly class Base64Url
{
    /**
     * Encode raw bytes as unpadded Base64URL.
     *
     * @param string $bytes Raw binary bytes.
     *
     * @return string Unpadded Base64URL string.
     */
    public static function encode(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    /**
     * Decode an unpadded Base64URL string into raw bytes.
     *
     * @param string $value Unpadded Base64URL string.
     *
     * @return string Raw binary bytes.
     *
     * @throws InvalidArgumentException When the value is not valid Base64URL.
     */
    public static function decode(string $value): string
    {
        if ($value === '' || preg_match('/^[A-Za-z0-9_-]+$/', $value) !== 1) {
            throw new InvalidArgumentException('Value must be a non-empty Base64URL string.');
        }

        $base64 = strtr($value, '-_', '+/');
        $padding = strlen($base64) % 4;

        if ($padding !== 0) {
            $base64 .= str_repeat('=', 4 - $padding);
        }

        $decoded = base64_decode($base64, true);
        if ($decoded === false) {
            throw new InvalidArgumentException('Value must decode as Base64URL.');
        }

        return $decoded;
    }
}
