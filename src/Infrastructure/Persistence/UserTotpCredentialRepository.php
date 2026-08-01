<?php

declare(strict_types=1);

namespace ModernAuthLab\Infrastructure\Persistence;

use PDO;

/**
 * SQLite-backed repository for TOTP enrollment records.
 *
 * The repository stores protected secret material and lifecycle metadata. It
 * does not generate, decrypt, or verify TOTP codes; those responsibilities stay
 * in the security/application layers.
 */
final readonly class UserTotpCredentialRepository
{
    /**
     * Receive the PDO connection used for TOTP persistence.
     *
     * @param PDO $pdo Configured SQLite connection.
     */
    public function __construct(
        private PDO $pdo,
    ) {}

    /**
     * Create a pending TOTP credential for a user.
     *
     * @param int $userId Owner user identifier.
     * @param string $secretCiphertext Encrypted TOTP secret payload.
     * @param string $secretNonce Nonce used to encrypt the secret payload.
     * @param string $secretKeyId Identifier for the encryption key used.
     * @param string $algorithm TOTP HMAC algorithm.
     * @param int $digits TOTP code length.
     * @param int $period TOTP time-step period in seconds.
     *
     * @return UserTotpCredential Created pending credential.
     *
     * @throws \PDOException When insertion fails.
     */
    public function createPending(
        int $userId,
        string $secretCiphertext,
        string $secretNonce,
        string $secretKeyId,
        string $algorithm,
        int $digits,
        int $period,
    ): UserTotpCredential {
        $statement = $this->pdo->prepare(
            'INSERT INTO user_totp_credentials (
                user_id,
                secret_ciphertext,
                secret_nonce,
                secret_key_id,
                algorithm,
                digits,
                period,
                status
            ) VALUES (
                :user_id,
                :secret_ciphertext,
                :secret_nonce,
                :secret_key_id,
                :algorithm,
                :digits,
                :period,
                :status
            )',
        );
        $statement->execute([
            'user_id' => $userId,
            'secret_ciphertext' => $secretCiphertext,
            'secret_nonce' => $secretNonce,
            'secret_key_id' => $secretKeyId,
            'algorithm' => $algorithm,
            'digits' => $digits,
            'period' => $period,
            'status' => 'pending',
        ]);

        return $this->findById((int) $this->pdo->lastInsertId());
    }

    /**
     * Find the current pending TOTP credential for a user.
     *
     * @param int $userId Owner user identifier.
     *
     * @return UserTotpCredential|null Pending credential or null.
     */
    public function findPendingByUserId(int $userId): ?UserTotpCredential
    {
        return $this->findOneByUserIdAndStatus($userId, 'pending');
    }

    /**
     * Find the current active TOTP credential for a user.
     *
     * @param int $userId Owner user identifier.
     *
     * @return UserTotpCredential|null Active credential or null.
     */
    public function findActiveByUserId(int $userId): ?UserTotpCredential
    {
        return $this->findOneByUserIdAndStatus($userId, 'active');
    }

    /**
     * Mark a pending credential as active after the user proves possession.
     *
     * @param int $id TOTP credential identifier.
     *
     * @return UserTotpCredential Confirmed active credential.
     */
    public function confirm(int $id): UserTotpCredential
    {
        $statement = $this->pdo->prepare(
            "UPDATE user_totp_credentials
                SET status = 'active',
                    confirmed_at = CURRENT_TIMESTAMP,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = :id AND status = 'pending'",
        );
        $statement->execute(['id' => $id]);

        return $this->findById($id);
    }

    /**
     * Revoke a credential so it can no longer be used for MFA.
     *
     * @param int $id TOTP credential identifier.
     *
     * @return UserTotpCredential Revoked credential.
     */
    public function revoke(int $id): UserTotpCredential
    {
        $statement = $this->pdo->prepare(
            "UPDATE user_totp_credentials
                SET status = 'revoked',
                    revoked_at = CURRENT_TIMESTAMP,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = :id AND status != 'revoked'",
        );
        $statement->execute(['id' => $id]);

        return $this->findById($id);
    }

    /**
     * Store the last accepted TOTP time step for future anti-replay checks.
     *
     * @param int $id TOTP credential identifier.
     * @param int $timeStep Accepted TOTP time step.
     *
     * @return UserTotpCredential Updated credential.
     */
    public function recordLastUsedTimeStep(int $id, int $timeStep): UserTotpCredential
    {
        $statement = $this->pdo->prepare(
            'UPDATE user_totp_credentials
                SET last_used_time_step = :time_step,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = :id
                    AND (last_used_time_step IS NULL OR last_used_time_step < :time_step)',
        );
        $statement->execute([
            'id' => $id,
            'time_step' => $timeStep,
        ]);

        return $this->findById($id);
    }

    private function findById(int $id): UserTotpCredential
    {
        $statement = $this->pdo->prepare(
            'SELECT
                id,
                user_id,
                secret_ciphertext,
                secret_nonce,
                secret_key_id,
                algorithm,
                digits,
                period,
                status,
                confirmed_at,
                last_used_time_step,
                revoked_at,
                created_at,
                updated_at
            FROM user_totp_credentials
            WHERE id = :id',
        );
        $statement->execute(['id' => $id]);
        $row = $statement->fetch();

        if (! is_array($row)) {
            throw new \RuntimeException(sprintf('TOTP credential "%d" was not found.', $id));
        }

        return $this->mapRowToCredential($row);
    }

    private function findOneByUserIdAndStatus(int $userId, string $status): ?UserTotpCredential
    {
        $statement = $this->pdo->prepare(
            'SELECT
                id,
                user_id,
                secret_ciphertext,
                secret_nonce,
                secret_key_id,
                algorithm,
                digits,
                period,
                status,
                confirmed_at,
                last_used_time_step,
                revoked_at,
                created_at,
                updated_at
            FROM user_totp_credentials
            WHERE user_id = :user_id AND status = :status
            ORDER BY id DESC
            LIMIT 1',
        );
        $statement->execute([
            'user_id' => $userId,
            'status' => $status,
        ]);
        $row = $statement->fetch();

        if (! is_array($row)) {
            return null;
        }

        return $this->mapRowToCredential($row);
    }

    /**
     * @param array<string, mixed> $row Raw database row.
     *
     * @return UserTotpCredential Hydrated TOTP credential record.
     */
    private function mapRowToCredential(array $row): UserTotpCredential
    {
        return new UserTotpCredential(
            (int) $row['id'],
            (int) $row['user_id'],
            (string) $row['secret_ciphertext'],
            (string) $row['secret_nonce'],
            (string) $row['secret_key_id'],
            (string) $row['algorithm'],
            (int) $row['digits'],
            (int) $row['period'],
            (string) $row['status'],
            $row['confirmed_at'] === null ? null : (string) $row['confirmed_at'],
            $row['last_used_time_step'] === null ? null : (int) $row['last_used_time_step'],
            $row['revoked_at'] === null ? null : (string) $row['revoked_at'],
            (string) $row['created_at'],
            (string) $row['updated_at'],
        );
    }
}
