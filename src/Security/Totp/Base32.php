<?php

declare(strict_types=1);

namespace ModernAuthLab\Security\Totp;

use InvalidArgumentException;

/**
 * RFC 4648 Base32 encoder/decoder for TOTP secrets.
 *
 * Authenticator apps expect TOTP secrets to be provisioned as Base32 text in
 * `otpauth://` URIs. This class keeps that encoding explicit and dependency
 * free so the TOTP implementation remains easy to audit.
 */
final readonly class Base32
{
    private const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    /**
     * Encode raw secret bytes as unpadded Base32 text.
     *
     * @param string $bytes Raw binary data.
     *
     * @return string Base32 encoded data without `=` padding.
     */
    public static function encode(string $bytes): string
    {
        if ($bytes === '') {
            return '';
        }

        $bits = '';

        foreach (str_split($bytes) as $byte) {
            $bits .= str_pad(decbin(ord($byte)), 8, '0', STR_PAD_LEFT);
        }

        $encoded = '';

        foreach (str_split($bits, 5) as $chunk) {
            $encoded .= self::ALPHABET[bindec(str_pad($chunk, 5, '0', STR_PAD_RIGHT))];
        }

        return $encoded;
    }

    /**
     * Decode Base32 text into raw bytes.
     *
     * Input is case-insensitive and may contain spaces. Padding is accepted but
     * ignored because TOTP provisioning commonly uses unpadded Base32 secrets.
     *
     * @param string $base32 Base32 encoded data.
     *
     * @return string Raw binary data.
     *
     * @throws InvalidArgumentException When the input contains invalid Base32 characters.
     */
    public static function decode(string $base32): string
    {
        $normalized = strtoupper(str_replace([' ', "\t", "\n", "\r", '='], '', $base32));

        if ($normalized === '') {
            return '';
        }

        $bits = '';

        foreach (str_split($normalized) as $character) {
            $index = strpos(self::ALPHABET, $character);

            if ($index === false) {
                throw new InvalidArgumentException(sprintf('Invalid Base32 character "%s".', $character));
            }

            $bits .= str_pad(decbin($index), 5, '0', STR_PAD_LEFT);
        }

        $decoded = '';

        foreach (str_split($bits, 8) as $chunk) {
            if (strlen($chunk) < 8) {
                continue;
            }

            $decoded .= chr(bindec($chunk));
        }

        return $decoded;
    }
}
