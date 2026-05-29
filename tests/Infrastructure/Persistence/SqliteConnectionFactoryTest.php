<?php

declare(strict_types=1);

namespace ModernAuthLab\Tests\Infrastructure\Persistence;

use ModernAuthLab\Infrastructure\Persistence\DatabaseConfig;
use ModernAuthLab\Infrastructure\Persistence\SqliteConnectionFactory;
use PHPUnit\Framework\TestCase;

final class SqliteConnectionFactoryTest extends TestCase
{
    public function testCreatesDatabaseFileAndEnablesForeignKeys(): void
    {
        $databasePath = $this->temporaryDatabasePath();
        $factory = new SqliteConnectionFactory(new DatabaseConfig($databasePath));

        $pdo = $factory->connect();

        self::assertFileExists($databasePath);
        self::assertSame(1, (int) $pdo->query('PRAGMA foreign_keys')->fetchColumn());
    }

    private function temporaryDatabasePath(): string
    {
        $directory = sys_get_temp_dir() . '/modern-auth-lab-tests/' . bin2hex(random_bytes(8));

        return $directory . '/app.sqlite';
    }
}
