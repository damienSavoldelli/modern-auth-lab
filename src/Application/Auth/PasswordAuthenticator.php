<?php

declare(strict_types=1);

namespace ModernAuthLab\Application\Auth;

use ModernAuthLab\Infrastructure\Persistence\UserRepository;
use ModernAuthLab\Security\Password\PasswordHasher;

final readonly class PasswordAuthenticator
{
    public function __construct(
        private UserRepository $users,
        private PasswordHasher $passwords,
    ) {}

    public function authenticate(string $email, string $plainPassword): PasswordAuthenticationResult
    {
        $user = $this->users->findByEmail($email);

        if ($user === null) {
            return PasswordAuthenticationResult::failure();
        }

        if (! $this->passwords->verify($plainPassword, $user->passwordHash)) {
            return PasswordAuthenticationResult::failure();
        }

        return PasswordAuthenticationResult::success($user);
    }
}
