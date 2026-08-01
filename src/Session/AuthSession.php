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
    private const AUTH_USER_EMAIL_KEY = 'auth_user_email';
    private const AUTH_USER_ID_KEY = 'auth_user_id';

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
    public function markFullyAuthenticated(?int $userId = null, ?string $email = null): void
    {
        $this->storage[self::AUTH_STATE_KEY] = AuthSessionState::FullyAuthenticated->value;

        if ($userId !== null) {
            $this->storage[self::AUTH_USER_ID_KEY] = $userId;
        }

        if ($email !== null) {
            $this->storage[self::AUTH_USER_EMAIL_KEY] = $email;
        }
    }

    /**
     * Return the authenticated user id when the session carries one.
     *
     * @return int|null Authenticated user id or null.
     */
    public function userId(): ?int
    {
        $value = $this->storage[self::AUTH_USER_ID_KEY] ?? null;

        return is_int($value) ? $value : null;
    }

    /**
     * Return the authenticated user email when the session carries one.
     *
     * @return string|null Authenticated user email or null.
     */
    public function userEmail(): ?string
    {
        $value = $this->storage[self::AUTH_USER_EMAIL_KEY] ?? null;

        return is_string($value) && $value !== '' ? $value : null;
    }

    /**
     * Remove authentication state from the session.
     *
     * @return void
     */
    public function clearAuthentication(): void
    {
        unset(
            $this->storage[self::AUTH_STATE_KEY],
            $this->storage[self::AUTH_USER_ID_KEY],
            $this->storage[self::AUTH_USER_EMAIL_KEY],
        );
    }
}
