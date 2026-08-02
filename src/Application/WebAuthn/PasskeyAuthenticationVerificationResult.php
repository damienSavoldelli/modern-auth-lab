<?php

declare(strict_types=1);

namespace ModernAuthLab\Application\WebAuthn;

use ModernAuthLab\Infrastructure\Persistence\UserPasskeyCredential;

/**
 * Result returned after successful Passkey authentication verification.
 */
final readonly class PasskeyAuthenticationVerificationResult
{
    /**
     * @param int $userId Owner user identifier resolved from the stored credential.
     * @param UserPasskeyCredential $credential Credential whose signature was verified.
     */
    public function __construct(
        public int $userId,
        public UserPasskeyCredential $credential,
    ) {}
}
