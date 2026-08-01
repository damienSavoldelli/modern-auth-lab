<?php

declare(strict_types=1);

namespace ModernAuthLab\Application\Totp;

use ModernAuthLab\Infrastructure\Persistence\UserTotpCredential;

/**
 * Result returned when a TOTP enrollment is started or resumed.
 *
 * The provisioning URI contains the user TOTP secret and must only be shown to
 * the authenticated user during setup.
 */
final readonly class TotpEnrollmentStartResult
{
    /**
     * @param UserTotpCredential $credential Pending TOTP credential.
     * @param string $provisioningUri Secret-bearing `otpauth://` provisioning URI.
     * @param string $secretBase32 Base32 secret shown only during setup.
     * @param bool $created True when this call created a new pending credential.
     */
    public function __construct(
        public UserTotpCredential $credential,
        public string $provisioningUri,
        public string $secretBase32,
        public bool $created,
    ) {}
}
