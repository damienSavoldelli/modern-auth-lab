<?php

declare(strict_types=1);

namespace ModernAuthLab\Infrastructure\Persistence;

/**
 * Immutable Passkey credential row loaded from persistence.
 *
 * The record contains server-side WebAuthn material: credential identifier,
 * public key data, sign counter, metadata, and lifecycle state. It never
 * contains the authenticator private key.
 */
final readonly class UserPasskeyCredential
{
    /**
     * Hydrate a Passkey credential from trusted persistence data.
     *
     * @param int $id Database identifier.
     * @param int $userId Owner user identifier.
     * @param string $credentialId WebAuthn credential identifier encoded for storage.
     * @param string $publicKey Verified public key material encoded for storage.
     * @param int $signCount Last stored authenticator signature counter.
     * @param string $name User-facing credential label.
     * @param list<string> $transports Browser-reported transport hints.
     * @param string|null $attestationType Attestation format or local policy label.
     * @param string|null $aaguid Authenticator model identifier when available.
     * @param string $status Credential lifecycle status.
     * @param string|null $lastUsedAt Timestamp of last successful assertion.
     * @param string|null $revokedAt Timestamp when credential was revoked.
     * @param string $createdAt Creation timestamp from persistence.
     * @param string $updatedAt Last update timestamp from persistence.
     */
    public function __construct(
        public int $id,
        public int $userId,
        public string $credentialId,
        public string $publicKey,
        public int $signCount,
        public string $name,
        public array $transports,
        public ?string $attestationType,
        public ?string $aaguid,
        public string $status,
        public ?string $lastUsedAt,
        public ?string $revokedAt,
        public string $createdAt,
        public string $updatedAt,
    ) {}
}
