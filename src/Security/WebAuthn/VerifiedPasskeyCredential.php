<?php

declare(strict_types=1);

namespace ModernAuthLab\Security\WebAuthn;

/**
 * Credential material returned after successful WebAuthn attestation verification.
 *
 * Values are encoded for project persistence. The private key is never present:
 * it remains inside the authenticator.
 */
final readonly class VerifiedPasskeyCredential
{
    /**
     * @param string $credentialId Base64URL-encoded WebAuthn credential id.
     * @param string $publicKey Base64URL-encoded credential public key material.
     * @param int $signCount Initial authenticator signature counter.
     * @param list<string> $transports Browser/authenticator transport hints.
     * @param string $attestationType Verified attestation type.
     * @param string $aaguid Authenticator AAGUID when available.
     */
    public function __construct(
        public string $credentialId,
        public string $publicKey,
        public int $signCount,
        public array $transports,
        public string $attestationType,
        public string $aaguid,
    ) {}
}
