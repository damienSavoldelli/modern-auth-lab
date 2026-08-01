<?php

declare(strict_types=1);

namespace ModernAuthLab\Tests\Infrastructure\Persistence\Migrations;

use ModernAuthLab\Infrastructure\Persistence\MigrationRepository;
use ModernAuthLab\Infrastructure\Persistence\MigrationRunner;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateUsersTable;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateUserTotpRecoveryCodesTable;
use PDO;
use PHPUnit\Framework\TestCase;

final class CreateUserTotpRecoveryCodesTableTest extends TestCase
{
    public function testCreatesUserTotpRecoveryCodesTable(): void
    {
        $pdo = $this->createMigratedConnection();

        $statement = $pdo->query('PRAGMA table_info(user_totp_recovery_codes)');

        self::assertNotFalse($statement);
        $columns = $statement->fetchAll(PDO::FETCH_ASSOC);
        self::assertIsArray($columns);
        self::assertSame(
            [
                'id',
                'user_id',
                'code_hash',
                'status',
                'used_at',
                'revoked_at',
                'created_at',
                'updated_at',
            ],
            array_column($columns, 'name'),
        );
    }

    public function testRejectsRecoveryCodeForMissingUser(): void
    {
        $pdo = $this->createMigratedConnection();

        $this->expectException(\PDOException::class);

        $pdo->exec(
            "INSERT INTO user_totp_recovery_codes (user_id, code_hash, status)
                VALUES (999, 'hash', 'active')",
        );
    }

    public function testRejectsUnsupportedStatus(): void
    {
        $pdo = $this->createMigratedConnection();
        $pdo->exec("INSERT INTO users (email, password_hash) VALUES ('user@example.com', 'hash')");

        $this->expectException(\PDOException::class);

        $pdo->exec(
            "INSERT INTO user_totp_recovery_codes (user_id, code_hash, status)
                VALUES (1, 'hash', 'pending')",
        );
    }

    public function testRejectsDuplicateRecoveryCodeHash(): void
    {
        $pdo = $this->createMigratedConnection();
        $pdo->exec("INSERT INTO users (email, password_hash) VALUES ('user@example.com', 'hash')");
        $pdo->exec("INSERT INTO users (email, password_hash) VALUES ('other@example.com', 'hash')");
        $pdo->exec(
            "INSERT INTO user_totp_recovery_codes (user_id, code_hash, status)
                VALUES (1, 'duplicate-hash', 'active')",
        );

        $this->expectException(\PDOException::class);

        $pdo->exec(
            "INSERT INTO user_totp_recovery_codes (user_id, code_hash, status)
                VALUES (2, 'duplicate-hash', 'active')",
        );
    }

    private function createMigratedConnection(): PDO
    {
        $pdo = new PDO('sqlite::memory:');
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
        $pdo->exec('PRAGMA foreign_keys = ON');

        $runner = new MigrationRunner($pdo, new MigrationRepository($pdo), [
            new CreateUsersTable(),
            new CreateUserTotpRecoveryCodesTable(),
        ]);
        $runner->run();

        return $pdo;
    }
}
