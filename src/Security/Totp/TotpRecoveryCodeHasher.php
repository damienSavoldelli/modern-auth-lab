<?php

declare(strict_types=1);

namespace ModernAuthLab\Security\Totp;

/**
 * Hashes and verifies TOTP recovery codes.
 *
 * Recovery codes are bearer credentials. They use password-style one-way
 * hashing because the server only needs to verify submitted codes, not recover
 * the original value.
 */
final readonly class TotpRecoveryCodeHasher
{
    /**
     * @param string|int|null $algorithm PHP password hashing algorithm.
     * @param array<string, mixed> $options Algorithm-specific options.
     */
    public function __construct(
        private string|int|null $algorithm = PASSWORD_DEFAULT,
        private array $options = [],
    ) {}

    /**
     * Hash a recovery code before storage.
     *
     * @param string $code Plain recovery code.
     *
     * @return string Hash suitable for storage.
     */
    public function hash(string $code): string
    {
        return password_hash($this->normalize($code), $this->algorithm, $this->options);
    }

    /**
     * Verify a submitted recovery code against a stored hash.
     *
     * @param string $code Submitted recovery code.
     * @param string $hash Stored recovery-code hash.
     *
     * @return bool True when the submitted code matches the stored hash.
     */
    public function verify(string $code, string $hash): bool
    {
        return password_verify($this->normalize($code), $hash);
    }

    /**
     * Normalize recovery-code input before hashing or verification.
     *
     * @param string $code Plain or submitted recovery code.
     *
     * @return string Normalized recovery code.
     */
    private function normalize(string $code): string
    {
        return strtoupper(str_replace([' ', '-'], '', trim($code)));
    }
}
