<?php

declare(strict_types=1);

namespace ModernAuthLab\Infrastructure\Persistence;

use ModernAuthLab\Domain\User\User;
use PDO;

/**
 * SQLite-backed user repository.
 *
 * This class is the persistence boundary for user records. It stores password
 * hashes only; plain passwords are never accepted here.
 */
final readonly class UserRepository
{
    /**
     * Receive the PDO connection used for user persistence.
     */
    public function __construct(
        private PDO $pdo,
    ) {}

    /**
     * Persist a new user with an already computed password hash.
     */
    public function create(string $email, string $passwordHash): User
    {
        $statement = $this->pdo->prepare(
            'INSERT INTO users (email, password_hash) VALUES (:email, :password_hash)',
        );
        $statement->execute([
            'email' => $email,
            'password_hash' => $passwordHash,
        ]);

        return $this->findById((int) $this->pdo->lastInsertId());
    }

    /**
     * Find a user by email or return null for a missing account.
     */
    public function findByEmail(string $email): ?User
    {
        $statement = $this->pdo->prepare(
            'SELECT id, email, password_hash, created_at, updated_at FROM users WHERE email = :email',
        );
        $statement->execute(['email' => $email]);
        $row = $statement->fetch();

        if (! is_array($row)) {
            return null;
        }

        return $this->mapRowToUser($row);
    }

    private function findById(int $id): User
    {
        $statement = $this->pdo->prepare(
            'SELECT id, email, password_hash, created_at, updated_at FROM users WHERE id = :id',
        );
        $statement->execute(['id' => $id]);
        $row = $statement->fetch();

        if (! is_array($row)) {
            throw new \RuntimeException(sprintf('User "%d" was not found after creation.', $id));
        }

        return $this->mapRowToUser($row);
    }

    /**
     * @param array<string, mixed> $row
     */
    private function mapRowToUser(array $row): User
    {
        return new User(
            (int) $row['id'],
            (string) $row['email'],
            (string) $row['password_hash'],
            (string) $row['created_at'],
            (string) $row['updated_at'],
        );
    }
}
