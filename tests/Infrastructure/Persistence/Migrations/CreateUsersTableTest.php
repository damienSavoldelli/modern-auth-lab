<?php

declare(strict_types=1);

namespace ModernAuthLab\Tests\Infrastructure\Persistence\Migrations;

use ModernAuthLab\Infrastructure\Persistence\MigrationRepository;
use ModernAuthLab\Infrastructure\Persistence\MigrationRunner;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateUsersTable;
use PDO;
use PHPUnit\Framework\TestCase;

final class CreateUsersTableTest extends TestCase
{
    public function testCreatesUsersTable(): void
    {
        $pdo = $this->createInMemoryConnection();
        $runner = new MigrationRunner($pdo, new MigrationRepository($pdo), [new CreateUsersTable()]);

        $runner->run();

        $statement = $pdo->query('PRAGMA table_info(users)');

        self::assertNotFalse($statement);
        $columns = $statement->fetchAll(PDO::FETCH_ASSOC);
        self::assertIsArray($columns);
        self::assertSame(
            ['id', 'email', 'password_hash', 'created_at', 'updated_at'],
            array_column($columns, 'name'),
        );
    }

    public function testEnforcesUniqueEmail(): void
    {
        $pdo = $this->createInMemoryConnection();
        $runner = new MigrationRunner($pdo, new MigrationRepository($pdo), [new CreateUsersTable()]);
        $runner->run();

        $pdo->exec(
            "INSERT INTO users (email, password_hash) VALUES ('user@example.com', 'hash-one')",
        );

        $this->expectException(\PDOException::class);

        $pdo->exec(
            "INSERT INTO users (email, password_hash) VALUES ('user@example.com', 'hash-two')",
        );
    }

    private function createInMemoryConnection(): PDO
    {
        $pdo = new PDO('sqlite::memory:');
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $pdo->exec('PRAGMA foreign_keys = ON');

        return $pdo;
    }
}
