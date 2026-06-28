<?php

declare(strict_types=1);

namespace ModernAuthLab\Security\Password;

/**
 * Thin wrapper around PHP's native password APIs.
 *
 * Keeping this behind a project service makes tests and future algorithm policy
 * changes explicit without replacing the standard library implementation.
 */
final readonly class PasswordHasher
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
     * Hash a plain password with the configured PHP password algorithm.
     *
     * @param string $plainPassword Plain password received from a trusted caller.
     *
     * @return string Password hash suitable for storage.
     */
    public function hash(string $plainPassword): string
    {
        return password_hash($plainPassword, $this->algorithm, $this->options);
    }

    /**
     * Verify a plain password against a stored hash using PHP's safe verifier.
     *
     * @param string $plainPassword Submitted plain password.
     * @param string $passwordHash Stored password hash.
     *
     * @return bool True when the submitted password matches the stored hash.
     */
    public function verify(string $plainPassword, string $passwordHash): bool
    {
        return password_verify($plainPassword, $passwordHash);
    }

    /**
     * Check whether a stored hash should be upgraded to current policy.
     *
     * @param string $passwordHash Stored password hash.
     *
     * @return bool True when the hash should be recalculated with current policy.
     */
    public function needsRehash(string $passwordHash): bool
    {
        return password_needs_rehash($passwordHash, $this->algorithm, $this->options);
    }
}
