<?php

declare(strict_types=1);

namespace ModernAuthLab\Security\Totp;

use InvalidArgumentException;
use RuntimeException;
use SensitiveParameter;

/**
 * Encrypts and decrypts TOTP secrets before they cross the persistence boundary.
 *
 * The implementation uses libsodium secretbox, an authenticated symmetric
 * encryption primitive. It protects both confidentiality and integrity: a
 * modified ciphertext cannot be decrypted silently.
 */
final readonly class TotpSecretProtector
{
    private const KEY_BYTES = SODIUM_CRYPTO_SECRETBOX_KEYBYTES;
    private const NONCE_BYTES = SODIUM_CRYPTO_SECRETBOX_NONCEBYTES;

    /**
     * @param string $key Raw 32-byte encryption key.
     * @param string $keyId Stable identifier for the encryption key.
     *
     * @throws InvalidArgumentException When the key or key id is invalid.
     */
    public function __construct(
        #[SensitiveParameter]
        private string $key,
        private string $keyId,
    ) {
        if (strlen($key) !== self::KEY_BYTES) {
            throw new InvalidArgumentException('TOTP secret encryption key must contain exactly 32 bytes.');
        }

        if ($keyId === '') {
            throw new InvalidArgumentException('TOTP secret encryption key id cannot be empty.');
        }
    }

    /**
     * Protect a TOTP secret before persistence.
     *
     * @param TotpSecret $secret Plain TOTP secret held in memory.
     *
     * @return ProtectedTotpSecret Encrypted secret payload.
     *
     * @throws \Random\RandomException When secure nonce generation fails.
     */
    public function protect(TotpSecret $secret): ProtectedTotpSecret
    {
        $nonce = random_bytes(self::NONCE_BYTES);
        $ciphertext = sodium_crypto_secretbox($secret->bytes(), $nonce, $this->key);

        return new ProtectedTotpSecret(
            base64_encode($ciphertext),
            base64_encode($nonce),
            $this->keyId,
        );
    }

    /**
     * Decrypt a protected TOTP secret after loading it from persistence.
     *
     * @param ProtectedTotpSecret $protected Secret payload from persistence.
     *
     * @return TotpSecret Decrypted TOTP secret value object.
     *
     * @throws InvalidArgumentException When the key id does not match this protector.
     * @throws RuntimeException When the encrypted payload is malformed or tampered with.
     */
    public function reveal(ProtectedTotpSecret $protected): TotpSecret
    {
        if ($protected->keyId !== $this->keyId) {
            throw new InvalidArgumentException('Protected TOTP secret key id does not match the configured key.');
        }

        $nonce = base64_decode($protected->nonce, true);
        if ($nonce === false || strlen($nonce) !== self::NONCE_BYTES) {
            throw new RuntimeException('Protected TOTP secret nonce is invalid.');
        }

        $ciphertext = base64_decode($protected->ciphertext, true);
        if ($ciphertext === false || $ciphertext === '') {
            throw new RuntimeException('Protected TOTP secret ciphertext is invalid.');
        }

        $secret = sodium_crypto_secretbox_open($ciphertext, $nonce, $this->key);
        if ($secret === false) {
            throw new RuntimeException('Protected TOTP secret could not be decrypted.');
        }

        return TotpSecret::fromBase32(Base32::encode($secret));
    }
}
