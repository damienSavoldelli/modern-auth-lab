<?php

declare(strict_types=1);

namespace ModernAuthLab\Application\User;

use ModernAuthLab\Infrastructure\Persistence\UserRepository;
use ModernAuthLab\Security\Password\PasswordHasher;

/**
 * Creates the deterministic local development user.
 *
 * This is only a developer convenience for local testing. It is intentionally
 * explicit and must not become public registration behavior.
 */
final readonly class DevUserSeeder
{
    public const EMAIL = 'dev@example.com';
    public const PASSWORD = 'DevPassword123!';

    /**
     * Receive collaborators for local user lookup, creation, and password hashing.
     */
    public function __construct(
        private UserRepository $users,
        private PasswordHasher $passwords,
    ) {}

    /**
     * Create the development user if it does not already exist.
     */
    public function seed(): DevUserSeedResult
    {
        $existingUser = $this->users->findByEmail(self::EMAIL);

        if ($existingUser !== null) {
            return new DevUserSeedResult(false, $existingUser);
        }

        return new DevUserSeedResult(
            true,
            $this->users->create(self::EMAIL, $this->passwords->hash(self::PASSWORD)),
        );
    }
}
