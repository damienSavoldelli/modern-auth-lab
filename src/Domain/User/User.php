<?php

declare(strict_types=1);

namespace ModernAuthLab\Domain\User;

/**
 * Immutable user record loaded from persistence.
 *
 * The model currently carries the password hash because password verification
 * is still repository-backed and local. It must never expose or store a plain
 * password.
 */
final readonly class User
{
    /**
     * Hydrate a user record from trusted persistence data.
     *
     * @param int $id Database identifier.
     * @param string $email User email address.
     * @param string $passwordHash Stored password hash.
     * @param string $createdAt Creation timestamp from persistence.
     * @param string $updatedAt Last update timestamp from persistence.
     */
    public function __construct(
        public int $id,
        public string $email,
        public string $passwordHash,
        public string $createdAt,
        public string $updatedAt,
    ) {}
}
