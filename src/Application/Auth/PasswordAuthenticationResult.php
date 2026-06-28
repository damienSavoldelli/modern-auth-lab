<?php

declare(strict_types=1);

namespace ModernAuthLab\Application\Auth;

use ModernAuthLab\Domain\User\User;

/**
 * Immutable result returned by password authentication.
 *
 * The result deliberately exposes a success flag and an optional user instead
 * of throwing on invalid credentials. Invalid credentials are an expected
 * authentication outcome, not an exceptional runtime failure.
 */
final readonly class PasswordAuthenticationResult
{
    private function __construct(
        public bool $success,
        public ?User $user,
    ) {}

    /**
     * Create a successful authentication result for the verified user.
     */
    public static function success(User $user): self
    {
        return new self(true, $user);
    }

    /**
     * Create a generic failed authentication result.
     */
    public static function failure(): self
    {
        return new self(false, null);
    }
}
