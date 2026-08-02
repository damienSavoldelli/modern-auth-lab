<?php

declare(strict_types=1);

namespace ModernAuthLab\Infrastructure\Persistence;

use DateTimeImmutable;
use PDO;

/**
 * SQLite-backed repository for temporary WebAuthn challenges.
 *
 * The repository stores challenge state only. It does not verify WebAuthn
 * responses or decide whether a ceremony should be accepted.
 */
final readonly class WebAuthnChallengeRepository
{
    /**
     * Receive the PDO connection used for challenge persistence.
     *
     * @param PDO $pdo Configured SQLite connection.
     */
    public function __construct(
        private PDO $pdo,
    ) {}

    /**
     * Store a new unconsumed challenge for a user and purpose.
     *
     * @param int $userId User associated with this challenge.
     * @param string $purpose Challenge purpose.
     * @param string $challenge Base64URL-encoded challenge bytes.
     * @param DateTimeImmutable $expiresAt Expiration timestamp.
     *
     * @return WebAuthnChallenge Created challenge record.
     */
    public function create(int $userId, string $purpose, string $challenge, DateTimeImmutable $expiresAt): WebAuthnChallenge
    {
        $statement = $this->pdo->prepare(
            'INSERT INTO webauthn_challenges (user_id, purpose, challenge, expires_at)
                VALUES (:user_id, :purpose, :challenge, :expires_at)',
        );
        $statement->execute([
            'user_id' => $userId,
            'purpose' => $purpose,
            'challenge' => $challenge,
            'expires_at' => $expiresAt->format('Y-m-d H:i:s'),
        ]);

        return $this->findById((int) $this->pdo->lastInsertId());
    }

    /**
     * Find an unconsumed challenge for a user and purpose.
     *
     * @param int $userId User associated with this challenge.
     * @param string $purpose Challenge purpose.
     * @param string $challenge Base64URL-encoded challenge bytes.
     *
     * @return WebAuthnChallenge|null Matching unconsumed challenge or null.
     */
    public function findUnconsumed(int $userId, string $purpose, string $challenge): ?WebAuthnChallenge
    {
        $statement = $this->pdo->prepare(
            'SELECT
                id,
                user_id,
                purpose,
                challenge,
                expires_at,
                consumed_at,
                created_at
            FROM webauthn_challenges
            WHERE user_id = :user_id
                AND purpose = :purpose
                AND challenge = :challenge
                AND consumed_at IS NULL
            LIMIT 1',
        );
        $statement->execute([
            'user_id' => $userId,
            'purpose' => $purpose,
            'challenge' => $challenge,
        ]);
        $row = $statement->fetch();

        if (! is_array($row)) {
            return null;
        }

        return $this->mapRowToChallenge($row);
    }

    /**
     * Mark a challenge as consumed after successful server-side verification.
     *
     * @param int $id Challenge identifier.
     *
     * @return WebAuthnChallenge Consumed challenge record.
     */
    public function consume(int $id): WebAuthnChallenge
    {
        $statement = $this->pdo->prepare(
            'UPDATE webauthn_challenges
                SET consumed_at = CURRENT_TIMESTAMP
                WHERE id = :id AND consumed_at IS NULL',
        );
        $statement->execute(['id' => $id]);

        return $this->findById($id);
    }

    private function findById(int $id): WebAuthnChallenge
    {
        $statement = $this->pdo->prepare(
            'SELECT
                id,
                user_id,
                purpose,
                challenge,
                expires_at,
                consumed_at,
                created_at
            FROM webauthn_challenges
            WHERE id = :id',
        );
        $statement->execute(['id' => $id]);
        $row = $statement->fetch();

        if (! is_array($row)) {
            throw new \RuntimeException(sprintf('WebAuthn challenge "%d" was not found.', $id));
        }

        return $this->mapRowToChallenge($row);
    }

    /**
     * @param array<string, mixed> $row Raw database row.
     *
     * @return WebAuthnChallenge Hydrated challenge record.
     */
    private function mapRowToChallenge(array $row): WebAuthnChallenge
    {
        return new WebAuthnChallenge(
            (int) $row['id'],
            (int) $row['user_id'],
            (string) $row['purpose'],
            (string) $row['challenge'],
            (string) $row['expires_at'],
            $row['consumed_at'] === null ? null : (string) $row['consumed_at'],
            (string) $row['created_at'],
        );
    }
}
