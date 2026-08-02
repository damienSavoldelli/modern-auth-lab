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
    private const AUTH_PENDING_MFA_METHOD_KEY = 'auth_pending_mfa_method';

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
     * The pending MFA challenge must retain the already verified user identity
     * so the second-factor controller can load the correct credential without
     * asking for the account identifier again.
     *
     * The optional pending method records which MFA factor the server chose for
     * this login attempt. Challenge controllers must reject sessions whose
     * pending method does not match their own factor to keep method selection
     * a server-side decision.
     *
     * @param int|null $userId Verified user id to carry into the MFA challenge.
     * @param string|null $email Verified user email to carry into the MFA challenge.
     * @param PendingMfaMethod|null $pendingMethod MFA method the server expects to verify.
     *
     * @return void
     */
    public function markMfaPending(
        ?int $userId = null,
        ?string $email = null,
        ?PendingMfaMethod $pendingMethod = null,
    ): void {
        $this->storage[self::AUTH_STATE_KEY] = AuthSessionState::MfaPending->value;
        $this->storeUserIdentity($userId, $email);

        if ($pendingMethod !== null) {
            $this->storage[self::AUTH_PENDING_MFA_METHOD_KEY] = $pendingMethod->value;
        }
    }

    /**
     * Return the MFA method the current session is waiting to verify.
     *
     * @return PendingMfaMethod|null Pending MFA method or null when unset.
     */
    public function pendingMfaMethod(): ?PendingMfaMethod
    {
        $value = $this->storage[self::AUTH_PENDING_MFA_METHOD_KEY] ?? null;

        if (! is_string($value)) {
            return null;
        }

        return PendingMfaMethod::tryFrom($value);
    }

    /**
     * Mark the session as fully authenticated for protected routes.
     *
     * @return void
     */
    public function markFullyAuthenticated(?int $userId = null, ?string $email = null): void
    {
        $this->storage[self::AUTH_STATE_KEY] = AuthSessionState::FullyAuthenticated->value;
        $this->storeUserIdentity($userId, $email);
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
            $this->storage[self::AUTH_PENDING_MFA_METHOD_KEY],
        );
    }

    /**
     * Store verified user identity values when they are available.
     *
     * @param int|null $userId Verified user id.
     * @param string|null $email Verified user email.
     *
     * @return void
     */
    private function storeUserIdentity(?int $userId, ?string $email): void
    {
        if ($userId !== null) {
            $this->storage[self::AUTH_USER_ID_KEY] = $userId;
        }

        if ($email !== null) {
            $this->storage[self::AUTH_USER_EMAIL_KEY] = $email;
        }
    }
}
