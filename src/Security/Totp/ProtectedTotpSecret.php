<?php

declare(strict_types=1);

namespace ModernAuthLab\Security\Totp;

use InvalidArgumentException;

/**
 * Encrypted representation of a TOTP secret ready for persistence.
 *
 * The value object intentionally exposes ciphertext metadata only. It must not
 * contain the decrypted secret because TOTP secrets are reusable MFA material.
 */
final readonly class ProtectedTotpSecret
{
    /**
     * @param string $ciphertext Base64-encoded encrypted secret payload.
     * @param string $nonce Base64-encoded nonce used for encryption.
     * @param string $keyId Identifier of the key used to encrypt the secret.
     */
    public function __construct(
        public string $ciphertext,
        public string $nonce,
        public string $keyId,
    ) {
        if ($ciphertext === '') {
            throw new InvalidArgumentException('Protected TOTP secret ciphertext cannot be empty.');
        }

        if ($nonce === '') {
            throw new InvalidArgumentException('Protected TOTP secret nonce cannot be empty.');
        }

        if ($keyId === '') {
            throw new InvalidArgumentException('Protected TOTP secret key id cannot be empty.');
        }
    }
}
