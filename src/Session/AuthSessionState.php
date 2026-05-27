<?php

declare(strict_types=1);

namespace ModernAuthLab\Session;

enum AuthSessionState: string
{
    case Anonymous = 'anonymous';
    case PasswordVerified = 'password_verified';
    case MfaPending = 'mfa_pending';
    case FullyAuthenticated = 'fully_authenticated';

    public function isFullyAuthenticated(): bool
    {
        return $this === self::FullyAuthenticated;
    }
}
