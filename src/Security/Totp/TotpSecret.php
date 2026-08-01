<?php

declare(strict_types=1);

namespace ModernAuthLab\Security\Totp;

use InvalidArgumentException;

/**
 * Security-critical TOTP shared secret.
 *
 * A TOTP secret is not the six-digit code shown by an authenticator app. It is
 * the long-lived shared key used by both the server and the app to compute
 * time-based codes.
 */
final readonly class TotpSecret
{
    private const DEFAULT_BYTES = 20;
    private const MIN_BYTES = 16;

    private function __construct(
        private string $base32,
        private string $bytes,
    ) {}

    /**
     * Generate a new random TOTP secret.
     *
     * @param int $bytes Number of random bytes to generate.
     *
     * @return self Generated TOTP secret.
     *
     * @throws InvalidArgumentException When the requested length is too short.
     * @throws \Random\RandomException When secure random generation fails.
     */
    public static function generate(int $bytes = self::DEFAULT_BYTES): self
    {
        if ($bytes < self::MIN_BYTES) {
            throw new InvalidArgumentException('TOTP secret length must be at least 16 bytes.');
        }

        return self::fromBytes(random_bytes($bytes));
    }

    /**
     * Recreate a TOTP secret from a Base32 provisioning value.
     *
     * @param string $base32 Base32 encoded TOTP secret.
     *
     * @return self TOTP secret value object.
     *
     * @throws InvalidArgumentException When the secret is empty, invalid, or too short.
     */
    public static function fromBase32(string $base32): self
    {
        $decoded = Base32::decode($base32);

        return self::fromBytes($decoded);
    }

    /**
     * Return the Base32 form used in `otpauth://` provisioning URIs.
     *
     * @return string Base32 encoded TOTP secret.
     */
    public function base32(): string
    {
        return $this->base32;
    }

    /**
     * Return the raw bytes needed by the future HOTP/TOTP verifier.
     *
     * @return string Raw secret bytes.
     */
    public function bytes(): string
    {
        return $this->bytes;
    }

    /**
     * Build a secret from raw bytes after enforcing project security policy.
     *
     * @param string $bytes Raw secret bytes.
     *
     * @return self TOTP secret value object.
     *
     * @throws InvalidArgumentException When the secret is too short.
     */
    private static function fromBytes(string $bytes): self
    {
        if (strlen($bytes) < self::MIN_BYTES) {
            throw new InvalidArgumentException('TOTP secret must contain at least 16 bytes.');
        }

        return new self(Base32::encode($bytes), $bytes);
    }
}
