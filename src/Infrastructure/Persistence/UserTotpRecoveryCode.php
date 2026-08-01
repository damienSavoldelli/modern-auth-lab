<?php

declare(strict_types=1);

namespace ModernAuthLab\Infrastructure\Persistence;

/**
 * Immutable recovery-code row loaded from persistence.
 *
 * The raw recovery code is never represented here. Only the one-way hash and
 * lifecycle metadata are allowed to cross the persistence boundary.
 */
final readonly class UserTotpRecoveryCode
{
    /**
     * Hydrate a TOTP recovery-code record from trusted persistence data.
     *
     * @param int $id Database identifier.
     * @param int $userId Owner user identifier.
     * @param string $codeHash One-way hash of the recovery code.
     * @param string $status Recovery-code lifecycle status.
     * @param string|null $usedAt Timestamp when the code was consumed.
     * @param string|null $revokedAt Timestamp when the code was revoked.
     * @param string $createdAt Creation timestamp from persistence.
     * @param string $updatedAt Last update timestamp from persistence.
     */
    public function __construct(
        public int $id,
        public int $userId,
        public string $codeHash,
        public string $status,
        public ?string $usedAt,
        public ?string $revokedAt,
        public string $createdAt,
        public string $updatedAt,
    ) {}
}
