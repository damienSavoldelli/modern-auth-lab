<?php

declare(strict_types=1);

namespace ModernAuthLab\Infrastructure\Persistence;

use PDO;

/**
 * SQLite-backed repository for Passkey credential records.
 *
 * The repository stores verified public credential material and lifecycle
 * metadata. WebAuthn parsing and cryptographic verification remain outside
 * persistence.
 */
final readonly class UserPasskeyCredentialRepository
{
    /**
     * Receive the PDO connection used for Passkey persistence.
     *
     * @param PDO $pdo Configured SQLite connection.
     */
    public function __construct(
        private PDO $pdo,
    ) {}

    /**
     * Store a newly verified active Passkey credential.
     *
     * @param int $userId Owner user identifier.
     * @param string $credentialId WebAuthn credential identifier encoded for storage.
     * @param string $publicKey Verified public key material encoded for storage.
     * @param int $signCount Initial authenticator signature counter.
     * @param string $name User-facing credential label.
     * @param list<string> $transports Browser-reported transport hints.
     * @param string|null $attestationType Attestation format or local policy label.
     * @param string|null $aaguid Authenticator model identifier when available.
     *
     * @return UserPasskeyCredential Created active Passkey credential.
     *
     * @throws \PDOException When insertion fails.
     */
    public function createActive(
        int $userId,
        string $credentialId,
        string $publicKey,
        int $signCount,
        string $name,
        array $transports = [],
        ?string $attestationType = null,
        ?string $aaguid = null,
    ): UserPasskeyCredential {
        $statement = $this->pdo->prepare(
            'INSERT INTO user_passkey_credentials (
                user_id,
                credential_id,
                public_key,
                sign_count,
                name,
                transports_json,
                attestation_type,
                aaguid,
                status
            ) VALUES (
                :user_id,
                :credential_id,
                :public_key,
                :sign_count,
                :name,
                :transports_json,
                :attestation_type,
                :aaguid,
                :status
            )',
        );
        $statement->execute([
            'user_id' => $userId,
            'credential_id' => $credentialId,
            'public_key' => $publicKey,
            'sign_count' => $signCount,
            'name' => $name,
            'transports_json' => json_encode($transports, JSON_THROW_ON_ERROR),
            'attestation_type' => $attestationType,
            'aaguid' => $aaguid,
            'status' => 'active',
        ]);

        return $this->findById((int) $this->pdo->lastInsertId());
    }

    /**
     * Find active Passkey credentials for a user.
     *
     * @param int $userId Owner user identifier.
     *
     * @return list<UserPasskeyCredential> Active credentials ordered by creation.
     */
    public function findActiveByUserId(int $userId): array
    {
        return $this->findManyByUserIdAndStatus($userId, 'active');
    }

    /**
     * Find an active Passkey credential by its WebAuthn credential id.
     *
     * @param string $credentialId WebAuthn credential identifier encoded for storage.
     *
     * @return UserPasskeyCredential|null Active credential or null.
     */
    public function findActiveByCredentialId(string $credentialId): ?UserPasskeyCredential
    {
        $statement = $this->pdo->prepare(
            'SELECT
                id,
                user_id,
                credential_id,
                public_key,
                sign_count,
                name,
                transports_json,
                attestation_type,
                aaguid,
                status,
                last_used_at,
                revoked_at,
                created_at,
                updated_at
            FROM user_passkey_credentials
            WHERE credential_id = :credential_id AND status = :status
            LIMIT 1',
        );
        $statement->execute([
            'credential_id' => $credentialId,
            'status' => 'active',
        ]);
        $row = $statement->fetch();

        if (! is_array($row)) {
            return null;
        }

        return $this->mapRowToCredential($row);
    }

    /**
     * Record successful use and update the signature counter.
     *
     * @param int $id Passkey credential identifier.
     * @param int $signCount Latest authenticator signature counter.
     *
     * @return UserPasskeyCredential Updated credential.
     */
    public function recordSuccessfulUse(int $id, int $signCount): UserPasskeyCredential
    {
        $statement = $this->pdo->prepare(
            'UPDATE user_passkey_credentials
                SET sign_count = :sign_count,
                    last_used_at = CURRENT_TIMESTAMP,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = :id AND status = :status',
        );
        $statement->execute([
            'id' => $id,
            'sign_count' => $signCount,
            'status' => 'active',
        ]);

        return $this->findById($id);
    }

    /**
     * Revoke one Passkey credential without deleting its audit history.
     *
     * @param int $id Passkey credential identifier.
     *
     * @return UserPasskeyCredential Revoked credential.
     */
    public function revoke(int $id): UserPasskeyCredential
    {
        $statement = $this->pdo->prepare(
            "UPDATE user_passkey_credentials
                SET status = 'revoked',
                    revoked_at = CURRENT_TIMESTAMP,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = :id AND status != 'revoked'",
        );
        $statement->execute(['id' => $id]);

        return $this->findById($id);
    }

    private function findById(int $id): UserPasskeyCredential
    {
        $statement = $this->pdo->prepare(
            'SELECT
                id,
                user_id,
                credential_id,
                public_key,
                sign_count,
                name,
                transports_json,
                attestation_type,
                aaguid,
                status,
                last_used_at,
                revoked_at,
                created_at,
                updated_at
            FROM user_passkey_credentials
            WHERE id = :id',
        );
        $statement->execute(['id' => $id]);
        $row = $statement->fetch();

        if (! is_array($row)) {
            throw new \RuntimeException(sprintf('Passkey credential "%d" was not found.', $id));
        }

        return $this->mapRowToCredential($row);
    }

    /**
     * @return list<UserPasskeyCredential>
     */
    private function findManyByUserIdAndStatus(int $userId, string $status): array
    {
        $statement = $this->pdo->prepare(
            'SELECT
                id,
                user_id,
                credential_id,
                public_key,
                sign_count,
                name,
                transports_json,
                attestation_type,
                aaguid,
                status,
                last_used_at,
                revoked_at,
                created_at,
                updated_at
            FROM user_passkey_credentials
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

        return array_map($this->mapRowToCredential(...), $rows);
    }

    /**
     * @param array<string, mixed> $row Raw database row.
     *
     * @return UserPasskeyCredential Hydrated Passkey credential record.
     */
    private function mapRowToCredential(array $row): UserPasskeyCredential
    {
        $transports = json_decode((string) $row['transports_json'], true, 512, JSON_THROW_ON_ERROR);

        if (! is_array($transports)) {
            throw new \RuntimeException('Stored Passkey transports must decode to a list.');
        }

        return new UserPasskeyCredential(
            (int) $row['id'],
            (int) $row['user_id'],
            (string) $row['credential_id'],
            (string) $row['public_key'],
            (int) $row['sign_count'],
            (string) $row['name'],
            array_values(array_map(static fn(mixed $transport): string => (string) $transport, $transports)),
            $row['attestation_type'] === null ? null : (string) $row['attestation_type'],
            $row['aaguid'] === null ? null : (string) $row['aaguid'],
            (string) $row['status'],
            $row['last_used_at'] === null ? null : (string) $row['last_used_at'],
            $row['revoked_at'] === null ? null : (string) $row['revoked_at'],
            (string) $row['created_at'],
            (string) $row['updated_at'],
        );
    }
}
