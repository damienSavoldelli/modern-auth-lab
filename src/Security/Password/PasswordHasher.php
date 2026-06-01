<?php

declare(strict_types=1);

namespace ModernAuthLab\Security\Password;

final readonly class PasswordHasher
{
    /**
     * @param array<string, mixed> $options
     */
    public function __construct(
        private string|int|null $algorithm = PASSWORD_DEFAULT,
        private array $options = [],
    ) {}

    public function hash(string $plainPassword): string
    {
        return password_hash($plainPassword, $this->algorithm, $this->options);
    }

    public function verify(string $plainPassword, string $passwordHash): bool
    {
        return password_verify($plainPassword, $passwordHash);
    }

    public function needsRehash(string $passwordHash): bool
    {
        return password_needs_rehash($passwordHash, $this->algorithm, $this->options);
    }
}
