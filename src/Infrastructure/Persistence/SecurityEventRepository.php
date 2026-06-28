<?php

declare(strict_types=1);

namespace ModernAuthLab\Infrastructure\Persistence;

use ModernAuthLab\Domain\Security\SecurityEventType;
use PDO;

/**
 * SQLite-backed repository for authentication security events.
 *
 * The repository records a narrow audit trail. It intentionally avoids secrets,
 * tokens, session ids, and arbitrary request payloads.
 */
final readonly class SecurityEventRepository
{
    /**
     * Receive the PDO connection used for audit persistence.
     *
     * @param PDO $pdo Configured SQLite connection.
     */
    public function __construct(
        private PDO $pdo,
    ) {}

    /**
     * Persist one security event.
     *
     * @param SecurityEventType $type Event vocabulary value.
     * @param int|null $userId Authenticated user id when known.
     * @param string|null $email Submitted or known email when relevant.
     * @param string $clientIp Server-observed client IP.
     *
     * @return void
     *
     * @throws \PDOException When insertion fails.
     */
    public function record(
        SecurityEventType $type,
        ?int $userId,
        ?string $email,
        string $clientIp,
    ): void {
        // Keep the first audit trail deliberately small: no secrets, no tokens,
        // no raw request payloads, and no free-form metadata yet.
        $statement = $this->pdo->prepare(
            'INSERT INTO security_events (type, user_id, email, client_ip)
                VALUES (:type, :user_id, :email, :client_ip)',
        );
        $statement->execute([
            'type' => $type->value,
            'user_id' => $userId,
            'email' => $email,
            'client_ip' => $clientIp,
        ]);
    }

    /**
     * Intended for tests and local inspection while the project has no security
     * event query use case. Production-facing queries should be explicit.
     *
     * @return list<array<string, mixed>> Security event rows.
     */
    public function all(): array
    {
        $statement = $this->pdo->query(
            'SELECT id, type, user_id, email, client_ip, created_at FROM security_events ORDER BY id ASC',
        );

        if ($statement === false) {
            return [];
        }

        $rows = $statement->fetchAll(PDO::FETCH_ASSOC);

        return is_array($rows) ? $rows : [];
    }
}
