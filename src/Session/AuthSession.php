<?php

declare(strict_types=1);

namespace ModernAuthLab\Session;

final class AuthSession
{
    private const AUTH_STATE_KEY = 'auth_state';

    /**
     * @param array<string, mixed> $storage
     */
    public function __construct(
        private array &$storage,
    ) {}

    public function state(): AuthSessionState
    {
        $value = $this->storage[self::AUTH_STATE_KEY] ?? null;

        if (! is_string($value)) {
            return AuthSessionState::Anonymous;
        }

        return AuthSessionState::tryFrom($value) ?? AuthSessionState::Anonymous;
    }

    public function markPasswordVerified(): void
    {
        $this->storage[self::AUTH_STATE_KEY] = AuthSessionState::PasswordVerified->value;
    }

    public function markMfaPending(): void
    {
        $this->storage[self::AUTH_STATE_KEY] = AuthSessionState::MfaPending->value;
    }

    public function markFullyAuthenticated(): void
    {
        $this->storage[self::AUTH_STATE_KEY] = AuthSessionState::FullyAuthenticated->value;
    }

    public function clearAuthentication(): void
    {
        unset($this->storage[self::AUTH_STATE_KEY]);
    }
}
