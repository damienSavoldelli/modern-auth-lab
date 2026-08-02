<?php

declare(strict_types=1);

namespace ModernAuthLab\Application\WebAuthn;

use ModernAuthLab\Infrastructure\Persistence\UserPasskeyCredential;

/**
 * Result returned after successful Passkey enrollment verification.
 */
final readonly class PasskeyEnrollmentVerificationResult
{
    /**
     * @param UserPasskeyCredential $credential Stored Passkey credential.
     */
    public function __construct(
        public UserPasskeyCredential $credential,
    ) {}
}
