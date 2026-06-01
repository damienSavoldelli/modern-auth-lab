<?php

declare(strict_types=1);

namespace ModernAuthLab\Application\Auth;

use ModernAuthLab\Domain\User\User;

final readonly class PasswordAuthenticationResult
{
    private function __construct(
        public bool $success,
        public ?User $user,
    ) {}

    public static function success(User $user): self
    {
        return new self(true, $user);
    }

    public static function failure(): self
    {
        return new self(false, null);
    }
}
