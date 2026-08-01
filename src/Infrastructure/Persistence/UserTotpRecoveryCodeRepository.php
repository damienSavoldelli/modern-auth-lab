<?php

declare(strict_types=1);

namespace ModernAuthLab\Infrastructure\Persistence;

use PDO;

/**
 * SQLite-backed repository for TOTP recovery-code records.
 *
 * The repository stores hashes only. Code generation and hash verification stay
 * outside persistence so raw recovery codes do not leak into database concerns.
 */
final readonly class UserTotpRecoveryCodeRepository
{
    /**
     * Receive the PDO connection used for recovery-code persistence.
     *
     * @param PDO $pdo Configured SQLite connection.
     */
    public function __construct(
        private PDO $pdo,
    ) {}

    /**
     * Store one active recovery-code hash for a user.
     *
     * @param int $userId Owner user identifier.
     * @param string $codeHash One-way recovery-code hash.
     *
     * @return UserTotpRecoveryCode Created recovery-code record.
     *
     * @throws \PDOException When insertion fails.
     */
    public function createActive(int $userId, string $codeHash): UserTotpRecoveryCode
    {
        $statement = $this->pdo->prepare(
            'INSERT INTO user_totp_recovery_codes (user_id, code_hash, status)
                VALUES (:user_id, :code_hash, :status)',
        );
        $statement->execute([
            'user_id' => $userId,
            'code_hash' => $codeHash,
            'status' => 'active',
        ]);

        return $this->findById((int) $this->pdo->lastInsertId());
    }

    /**
     * Find active recovery-code records for a user.
     *
     * @param int $userId Owner user identifier.
     *
     * @return list<UserTotpRecoveryCode> Active recovery-code records.
     */
    public function findActiveByUserId(int $userId): array
    {
        return $this->findManyByUserIdAndStatus($userId, 'active');
    }

    /**
     * Mark an active recovery code as used.
     *
     * @param int $id Recovery-code identifier.
     *
     * @return UserTotpRecoveryCode Used recovery-code record.
     */
    public function markUsed(int $id): UserTotpRecoveryCode
    {
        $statement = $this->pdo->prepare(
            "UPDATE user_totp_recovery_codes
                SET status = 'used',
                    used_at = CURRENT_TIMESTAMP,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = :id AND status = 'active'",
        );
        $statement->execute(['id' => $id]);

        return $this->findById($id);
    }

    /**
     * Revoke all active recovery codes for a user.
     *
     * @param int $userId Owner user identifier.
     *
     * @return void
     */
    public function revokeActiveByUserId(int $userId): void
    {
        $statement = $this->pdo->prepare(
            "UPDATE user_totp_recovery_codes
                SET status = 'revoked',
                    revoked_at = CURRENT_TIMESTAMP,
                    updated_at = CURRENT_TIMESTAMP
                WHERE user_id = :user_id AND status = 'active'",
        );
        $statement->execute(['user_id' => $userId]);
    }

    private function findById(int $id): UserTotpRecoveryCode
    {
        $statement = $this->pdo->prepare(
            'SELECT
                id,
                user_id,
                code_hash,
                status,
                used_at,
                revoked_at,
                created_at,
                updated_at
            FROM user_totp_recovery_codes
            WHERE id = :id',
        );
        $statement->execute(['id' => $id]);
        $row = $statement->fetch();

        if (! is_array($row)) {
            throw new \RuntimeException(sprintf('TOTP recovery code "%d" was not found.', $id));
        }

        return $this->mapRowToRecoveryCode($row);
    }

    /**
     * @return list<UserTotpRecoveryCode>
     */
    private function findManyByUserIdAndStatus(int $userId, string $status): array
    {
        $statement = $this->pdo->prepare(
            'SELECT
                id,
                user_id,
                code_hash,
                status,
                used_at,
                revoked_at,
                created_at,
                updated_at
            FROM user_totp_recovery_codes
            WHERE user_id = :user_id AND status = :status
            ORDER BY id ASC',
        );
        $statement->execute([
            'user_id' => $userId,
            'status' => $status,
        ]);
        $rows = $statement->fetchAll();

        if (! is_array($rows)) {
            return [];
        }

        return array_map($this->mapRowToRecoveryCode(...), $rows);
    }

    /**
     * @param array<string, mixed> $row Raw database row.
     *
     * @return UserTotpRecoveryCode Hydrated recovery-code record.
     */
    private function mapRowToRecoveryCode(array $row): UserTotpRecoveryCode
    {
        return new UserTotpRecoveryCode(
            (int) $row['id'],
            (int) $row['user_id'],
            (string) $row['code_hash'],
            (string) $row['status'],
            $row['used_at'] === null ? null : (string) $row['used_at'],
            $row['revoked_at'] === null ? null : (string) $row['revoked_at'],
            (string) $row['created_at'],
            (string) $row['updated_at'],
        );
    }
}
