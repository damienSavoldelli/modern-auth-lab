<?php

declare(strict_types=1);

namespace ModernAuthLab\Security\WebAuthn;

use ModernAuthLab\Infrastructure\Persistence\UserPasskeyCredential;

/**
 * Verifies a browser Passkey authentication assertion.
 *
 * The interface keeps application services independent of the WebAuthn library
 * used to perform low-level challenge, origin, RP ID, user presence, user
 * verification, signature, and sign-counter validation.
 */
interface PasskeyAssertionVerifier
{
    /**
     * Verify a browser assertion response for Passkey authentication.
     *
     * @param UserPasskeyCredential $credential Stored credential matching the browser response.
     * @param string $challenge Base64URL challenge previously issued by the server.
     * @param array<string, mixed> $assertion Browser assertion payload.
     *
     * @return VerifiedPasskeyAssertion Verified assertion carrying the updated sign counter.
     */
    public function verify(
        UserPasskeyCredential $credential,
        string $challenge,
        array $assertion,
    ): VerifiedPasskeyAssertion;
}
