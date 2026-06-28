<?php

declare(strict_types=1);

namespace ModernAuthLab\Application\User;

use ModernAuthLab\Infrastructure\Persistence\UserRepository;
use ModernAuthLab\Security\Password\PasswordHasher;

final readonly class DevUserSeeder
{
    public const EMAIL = 'dev@example.com';
    public const PASSWORD = 'DevPassword123!';

    public function __construct(
        private UserRepository $users,
        private PasswordHasher $passwords,
    ) {}

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
