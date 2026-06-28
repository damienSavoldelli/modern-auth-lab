<?php

declare(strict_types=1);

namespace ModernAuthLab\Session;

/**
 * Explicit authentication state machine values stored in the PHP session.
 *
 * Modeling states as an enum prevents the project from collapsing partial
 * authentication, MFA-pending states, and full authentication into one boolean.
 */
enum AuthSessionState: string
{
    case Anonymous = 'anonymous';
    case PasswordVerified = 'password_verified';
    case MfaPending = 'mfa_pending';
    case FullyAuthenticated = 'fully_authenticated';

    /**
     * Determine whether the current state may access protected routes.
     *
     * @return bool True when the state represents full authentication.
     */
    public function isFullyAuthenticated(): bool
    {
        return $this === self::FullyAuthenticated;
    }
}
