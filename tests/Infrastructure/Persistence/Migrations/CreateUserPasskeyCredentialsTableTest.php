<?php

declare(strict_types=1);

namespace ModernAuthLab\Tests\Infrastructure\Persistence\Migrations;

use ModernAuthLab\Infrastructure\Persistence\MigrationRepository;
use ModernAuthLab\Infrastructure\Persistence\MigrationRunner;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateUserPasskeyCredentialsTable;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateUsersTable;
use PDO;
use PHPUnit\Framework\TestCase;

final class CreateUserPasskeyCredentialsTableTest extends TestCase
{
    public function testCreatesUserPasskeyCredentialsTable(): void
    {
        $pdo = $this->createMigratedConnection();

        $statement = $pdo->query('PRAGMA table_info(user_passkey_credentials)');

        self::assertNotFalse($statement);
        $columns = $statement->fetchAll(PDO::FETCH_ASSOC);
        self::assertIsArray($columns);
        self::assertSame(
            [
                'id',
                'user_id',
                'credential_id',
                'public_key',
                'sign_count',
                'name',
                'transports_json',
                'attestation_type',
                'aaguid',
                'status',
                'last_used_at',
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
            "INSERT INTO user_passkey_credentials (user_id, credential_id, public_key, name, status)
                VALUES (999, 'credential-id', 'public-key', 'Security key', 'active')",
        );
    }

    public function testRejectsUnsupportedStatus(): void
    {
        $pdo = $this->createMigratedConnection();
        $pdo->exec("INSERT INTO users (email, password_hash) VALUES ('user@example.com', 'hash')");

        $this->expectException(\PDOException::class);

        $pdo->exec(
            "INSERT INTO user_passkey_credentials (user_id, credential_id, public_key, name, status)
                VALUES (1, 'credential-id', 'public-key', 'Security key', 'pending')",
        );
    }

    public function testRejectsDuplicateCredentialId(): void
    {
        $pdo = $this->createMigratedConnection();
        $pdo->exec("INSERT INTO users (email, password_hash) VALUES ('user@example.com', 'hash')");
        $pdo->exec("INSERT INTO users (email, password_hash) VALUES ('other@example.com', 'hash')");
        $pdo->exec(
            "INSERT INTO user_passkey_credentials (user_id, credential_id, public_key, name, status)
                VALUES (1, 'duplicate-credential', 'public-key', 'First key', 'active')",
        );

        $this->expectException(\PDOException::class);

        $pdo->exec(
            "INSERT INTO user_passkey_credentials (user_id, credential_id, public_key, name, status)
                VALUES (2, 'duplicate-credential', 'other-public-key', 'Second key', 'active')",
        );
    }

    public function testRejectsNegativeSignCount(): void
    {
        $pdo = $this->createMigratedConnection();
        $pdo->exec("INSERT INTO users (email, password_hash) VALUES ('user@example.com', 'hash')");

        $this->expectException(\PDOException::class);

        $pdo->exec(
            "INSERT INTO user_passkey_credentials (user_id, credential_id, public_key, sign_count, name, status)
                VALUES (1, 'credential-id', 'public-key', -1, 'Security key', 'active')",
        );
    }

    public function testRejectsInvalidTransportJson(): void
    {
        $pdo = $this->createMigratedConnection();
        $pdo->exec("INSERT INTO users (email, password_hash) VALUES ('user@example.com', 'hash')");

        $this->expectException(\PDOException::class);

        $pdo->exec(
            "INSERT INTO user_passkey_credentials (
                user_id,
                credential_id,
                public_key,
                name,
                transports_json,
                status
            ) VALUES (
                1,
                'credential-id',
                'public-key',
                'Security key',
                'not-json',
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
            new CreateUserPasskeyCredentialsTable(),
        ]);
        $runner->run();

        return $pdo;
    }
}
