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
    case TotpDisableSucceeded = 'totp_disable_succeeded';
    case TotpDisableFailed = 'totp_disable_failed';
    case TotpRecoveryCodesGenerated = 'totp_recovery_codes_generated';
    case TotpRecoveryCodesGenerationFailed = 'totp_recovery_codes_generation_failed';
    case LogoutSucceeded = 'logout_succeeded';
    case LogoutCsrfFailed = 'logout_csrf_failed';
    case PasskeyEnrollmentSucceeded = 'passkey_enrollment_succeeded';
    case PasskeyEnrollmentFailed = 'passkey_enrollment_failed';
    case PasskeyAuthenticationSucceeded = 'passkey_authentication_succeeded';
    case PasskeyAuthenticationFailed = 'passkey_authentication_failed';
    case PasskeyRevoked = 'passkey_revoked';
}
