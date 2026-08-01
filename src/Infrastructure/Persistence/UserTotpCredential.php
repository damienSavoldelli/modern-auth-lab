<?php

declare(strict_types=1);

namespace ModernAuthLab\Infrastructure\Persistence;

/**
 * Immutable TOTP credential row loaded from persistence.
 *
 * Secret material is intentionally represented as protected storage fields.
 * Application workflows must decrypt it only at the boundary that needs to
 * generate or verify a TOTP code.
 */
final readonly class UserTotpCredential
{
    /**
     * Hydrate a TOTP credential from trusted persistence data.
     *
     * @param int $id Database identifier.
     * @param int $userId Owner user identifier.
     * @param string $secretCiphertext Encrypted TOTP secret payload.
     * @param string $secretNonce Nonce used to encrypt the secret payload.
     * @param string $secretKeyId Identifier for the encryption key used.
     * @param string $algorithm TOTP HMAC algorithm.
     * @param int $digits TOTP code length.
     * @param int $period TOTP time-step period in seconds.
     * @param string $status Enrollment lifecycle status.
     * @param string|null $confirmedAt Timestamp when enrollment was confirmed.
     * @param int|null $lastUsedTimeStep Last accepted TOTP time step.
     * @param string|null $revokedAt Timestamp when credential was revoked.
     * @param string $createdAt Creation timestamp from persistence.
     * @param string $updatedAt Last update timestamp from persistence.
     */
    public function __construct(
        public int $id,
        public int $userId,
        public string $secretCiphertext,
        public string $secretNonce,
        public string $secretKeyId,
        public string $algorithm,
        public int $digits,
        public int $period,
        public string $status,
        public ?string $confirmedAt,
        public ?int $lastUsedTimeStep,
        public ?string $revokedAt,
        public string $createdAt,
        public string $updatedAt,
    ) {}
}
