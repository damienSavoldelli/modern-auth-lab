<?php

declare(strict_types=1);

namespace ModernAuthLab\Infrastructure\Persistence;

use ModernAuthLab\Domain\Security\SecurityEventType;
use PDO;

final readonly class SecurityEventRepository
{
    public function __construct(
        private PDO $pdo,
    ) {}

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
     * @return list<array<string, mixed>>
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
