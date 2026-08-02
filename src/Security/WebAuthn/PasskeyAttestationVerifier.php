<?php

declare(strict_types=1);

namespace ModernAuthLab\Security\WebAuthn;

use ModernAuthLab\Domain\User\User;

/**
 * Verifies a browser Passkey enrollment response.
 *
 * Implementations may use a WebAuthn library, but callers receive a project
 * value object so application services are not coupled to library internals.
 */
interface PasskeyAttestationVerifier
{
    /**
     * Verify a browser attestation response for Passkey enrollment.
     *
     * @param User $user Existing user enrolling a Passkey.
     * @param string $challenge Base64URL challenge previously issued by the server.
     * @param array<string, mixed> $credential Browser credential response payload.
     *
     * @return VerifiedPasskeyCredential Verified credential material.
     */
    public function verify(User $user, string $challenge, array $credential): VerifiedPasskeyCredential;
}
