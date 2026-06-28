<?php

declare(strict_types=1);

namespace ModernAuthLab\Tests\Infrastructure\Persistence\Migrations;

use ModernAuthLab\Infrastructure\Persistence\MigrationRepository;
use ModernAuthLab\Infrastructure\Persistence\MigrationRunner;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateSecurityEventsTable;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateUsersTable;
use PDO;
use PHPUnit\Framework\TestCase;

final class CreateSecurityEventsTableTest extends TestCase
{
    public function testCreatesSecurityEventsTable(): void
    {
        $pdo = $this->createInMemoryConnection();
        $runner = new MigrationRunner($pdo, new MigrationRepository($pdo), [
            new CreateUsersTable(),
            new CreateSecurityEventsTable(),
        ]);

        $runner->run();

        $statement = $pdo->query('PRAGMA table_info(security_events)');

        self::assertNotFalse($statement);
        $columns = $statement->fetchAll(PDO::FETCH_ASSOC);
        self::assertIsArray($columns);
        self::assertSame(
            ['id', 'type', 'user_id', 'email', 'client_ip', 'created_at'],
            array_column($columns, 'name'),
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
