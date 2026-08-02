<?php

declare(strict_types=1);

namespace ModernAuthLab\Security\WebAuthn;

/**
 * Result returned after successful WebAuthn assertion verification.
 *
 * The assertion proves control of an existing credential. The verifier returns
 * the resolved credential id and the updated sign counter so the application
 * layer can persist last-used metadata without depending on library types.
 */
final readonly class VerifiedPasskeyAssertion
{
    /**
     * @param string $credentialId Base64URL-encoded WebAuthn credential id used by the assertion.
     * @param int $signCount Authenticator signature counter reported by the assertion.
     */
    public function __construct(
        public string $credentialId,
        public int $signCount,
    ) {}
}
