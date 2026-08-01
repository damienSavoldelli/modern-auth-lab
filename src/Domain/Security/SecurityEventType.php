<?php

declare(strict_types=1);

namespace ModernAuthLab\Domain\Security;

/**
 * Closed vocabulary for auditable authentication and session events.
 *
 * Security events are intentionally modeled as an enum so new flows cannot
 * invent ad hoc event names in controllers.
 */
enum SecurityEventType: string
{
    case PasswordLoginSucceeded = 'password_login_succeeded';
    case PasswordLoginFailed = 'password_login_failed';
    case TotpChallengeSucceeded = 'totp_challenge_succeeded';
    case TotpChallengeFailed = 'totp_challenge_failed';
    case TotpChallengeRateLimited = 'totp_challenge_rate_limited';
    case LogoutSucceeded = 'logout_succeeded';
    case LogoutCsrfFailed = 'logout_csrf_failed';
}
