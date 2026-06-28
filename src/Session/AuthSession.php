<?php

declare(strict_types=1);

namespace ModernAuthLab\Session;

/**
 * Authentication-state facade over session storage.
 *
 * The class centralizes how auth state is written and read, so controllers do
 * not manipulate raw session keys directly.
 */
final class AuthSession
{
    private const AUTH_STATE_KEY = 'auth_state';

    /**
     * @param array<string, mixed> $storage Session-backed auth storage.
     */
    public function __construct(
        private array &$storage,
    ) {}

    /**
     * Read the current authentication state, falling back safely to anonymous.
     *
     * @return AuthSessionState Current authentication state.
     */
    public function state(): AuthSessionState
    {
        $value = $this->storage[self::AUTH_STATE_KEY] ?? null;

        if (! is_string($value)) {
            return AuthSessionState::Anonymous;
        }

        return AuthSessionState::tryFrom($value) ?? AuthSessionState::Anonymous;
    }

    /**
     * Mark the session as having passed password verification only.
     *
     * @return void
     */
    public function markPasswordVerified(): void
    {
        $this->storage[self::AUTH_STATE_KEY] = AuthSessionState::PasswordVerified->value;
    }

    /**
     * Mark the session as waiting for MFA completion.
     *
     * @return void
     */
    public function markMfaPending(): void
    {
        $this->storage[self::AUTH_STATE_KEY] = AuthSessionState::MfaPending->value;
    }

    /**
     * Mark the session as fully authenticated for protected routes.
     *
     * @return void
     */
    public function markFullyAuthenticated(): void
    {
        $this->storage[self::AUTH_STATE_KEY] = AuthSessionState::FullyAuthenticated->value;
    }

    /**
     * Remove authentication state from the session.
     *
     * @return void
     */
    public function clearAuthentication(): void
    {
        unset($this->storage[self::AUTH_STATE_KEY]);
    }
}
