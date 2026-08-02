<?php

declare(strict_types=1);

namespace ModernAuthLab\Session;

/**
 * MFA method the current session is waiting to verify.
 *
 * The pending method is a server-side routing decision. A session in the
 * {@see AuthSessionState::MfaPending} state must not allow the browser to
 * substitute a different method than the one the server chose.
 */
enum PendingMfaMethod: string
{
    case Totp = 'totp';
    case Passkey = 'passkey';
}
