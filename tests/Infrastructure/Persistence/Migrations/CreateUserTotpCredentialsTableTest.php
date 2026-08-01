<?php

declare(strict_types=1);

namespace ModernAuthLab\Tests\Infrastructure\Persistence\Migrations;

use ModernAuthLab\Infrastructure\Persistence\MigrationRepository;
use ModernAuthLab\Infrastructure\Persistence\MigrationRunner;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateUsersTable;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateUserTotpCredentialsTable;
use PDO;
use PHPUnit\Framework\TestCase;

final class CreateUserTotpCredentialsTableTest extends TestCase
{
    public function testCreatesUserTotpCredentialsTable(): void
    {
        $pdo = $this->createMigratedConnection();

        $statement = $pdo->query('PRAGMA table_info(user_totp_credentials)');

        self::assertNotFalse($statement);
        $columns = $statement->fetchAll(PDO::FETCH_ASSOC);
        self::assertIsArray($columns);
        self::assertSame(
            [
                'id',
                'user_id',
                'secret_ciphertext',
                'secret_nonce',
                'secret_key_id',
                'algorithm',
                'digits',
                'period',
                'status',
                'confirmed_at',
                'last_used_time_step',
                'revoked_at',
                'created_at',
                'updated_at',
            ],
            array_column($columns, 'name'),
        );
    }

    public function testRejectsCredentialForMissingUser(): void
    {
        $pdo = $this->createMigratedConnection();

        $this->expectException(\PDOException::class);

        $pdo->exec(
            "INSERT INTO user_totp_credentials (
                user_id,
                secret_ciphertext,
                secret_nonce,
                secret_key_id,
                algorithm,
                digits,
                period,
                status
            ) VALUES (
                999,
                'ciphertext',
                'nonce',
                'local',
                'SHA1',
                6,
                30,
                'pending'
            )",
        );
    }

    public function testRejectsUnsupportedAlgorithm(): void
    {
        $pdo = $this->createMigratedConnection();
        $pdo->exec("INSERT INTO users (email, password_hash) VALUES ('user@example.com', 'hash')");

        $this->expectException(\PDOException::class);

        $pdo->exec(
            "INSERT INTO user_totp_credentials (
                user_id,
                secret_ciphertext,
                secret_nonce,
                secret_key_id,
                algorithm,
                digits,
                period,
                status
            ) VALUES (
                1,
                'ciphertext',
                'nonce',
                'local',
                'MD5',
                6,
                30,
                'pending'
            )",
        );
    }

    public function testAllowsOnlyOneCurrentCredentialPerUser(): void
    {
        $pdo = $this->createMigratedConnection();
        $pdo->exec("INSERT INTO users (email, password_hash) VALUES ('user@example.com', 'hash')");
        $pdo->exec(
            "INSERT INTO user_totp_credentials (
                user_id,
                secret_ciphertext,
                secret_nonce,
                secret_key_id,
                algorithm,
                digits,
                period,
                status
            ) VALUES (
                1,
                'ciphertext-one',
                'nonce-one',
                'local',
                'SHA1',
                6,
                30,
                'pending'
            )",
        );

        $this->expectException(\PDOException::class);

        $pdo->exec(
            "INSERT INTO user_totp_credentials (
                user_id,
                secret_ciphertext,
                secret_nonce,
                secret_key_id,
                algorithm,
                digits,
                period,
                status
            ) VALUES (
                1,
                'ciphertext-two',
                'nonce-two',
                'local',
                'SHA1',
                6,
                30,
                'active'
            )",
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
            new CreateUserTotpCredentialsTable(),
        ]);
        $runner->run();

        return $pdo;
    }
}
