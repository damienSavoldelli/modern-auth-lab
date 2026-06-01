<?php

declare(strict_types=1);

namespace ModernAuthLab\Tests\Infrastructure\Persistence;

use ModernAuthLab\Infrastructure\Persistence\Migration;
use ModernAuthLab\Infrastructure\Persistence\MigrationRepository;
use ModernAuthLab\Infrastructure\Persistence\MigrationRunner;
use PDO;
use PHPUnit\Framework\TestCase;

final class MigrationRunnerTest extends TestCase
{
    public function testRunsPendingMigrationsAndRecordsVersions(): void
    {
        $pdo = $this->createInMemoryConnection();
        $repository = new MigrationRepository($pdo);
        $migration = new class implements Migration {
            public function version(): string
            {
                return '0002_create_example_table';
            }

            public function up(): string
            {
                return 'CREATE TABLE example_records (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL);';
            }
        };

        $runner = new MigrationRunner($pdo, $repository, [$migration]);
        $runner->run();

        self::assertTrue($repository->has('0002_create_example_table'));
        self::assertSame(['0002_create_example_table'], $repository->all());

        $statement = $pdo->query("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'example_records'");

        self::assertNotFalse($statement);
        self::assertSame('example_records', $statement->fetchColumn());
    }

    public function testSkipsAlreadyAppliedMigrations(): void
    {
        $pdo = $this->createInMemoryConnection();
        $repository = new MigrationRepository($pdo);
        $migration = new class implements Migration {
            public function version(): string
            {
                return '0002_create_example_table';
            }

            public function up(): string
            {
                return 'CREATE TABLE example_records (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL);';
            }
        };

        $runner = new MigrationRunner($pdo, $repository, [$migration]);
        $runner->run();
        $runner->run();

        self::assertSame(['0002_create_example_table'], $repository->all());
    }

    private function createInMemoryConnection(): PDO
    {
        $pdo = new PDO('sqlite::memory:');
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $pdo->exec('PRAGMA foreign_keys = ON');

        return $pdo;
    }
}
