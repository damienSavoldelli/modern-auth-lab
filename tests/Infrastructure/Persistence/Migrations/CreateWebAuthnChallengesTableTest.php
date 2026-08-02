<?php

declare(strict_types=1);

namespace ModernAuthLab\Tests\Infrastructure\Persistence\Migrations;

use ModernAuthLab\Infrastructure\Persistence\MigrationRepository;
use ModernAuthLab\Infrastructure\Persistence\MigrationRunner;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateUsersTable;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateWebAuthnChallengesTable;
use PDO;
use PHPUnit\Framework\TestCase;

final class CreateWebAuthnChallengesTableTest extends TestCase
{
    public function testCreatesWebAuthnChallengesTable(): void
    {
        $pdo = $this->createMigratedConnection();

        $statement = $pdo->query('PRAGMA table_info(webauthn_challenges)');

        self::assertNotFalse($statement);
        $columns = $statement->fetchAll(PDO::FETCH_ASSOC);
        self::assertIsArray($columns);
        self::assertSame(
            [
                'id',
                'user_id',
                'purpose',
                'challenge',
                'expires_at',
                'consumed_at',
                'created_at',
            ],
            array_column($columns, 'name'),
        );
    }

    public function testRejectsChallengeForMissingUser(): void
    {
        $pdo = $this->createMigratedConnection();

        $this->expectException(\PDOException::class);

        $pdo->exec(
            "INSERT INTO webauthn_challenges (user_id, purpose, challenge, expires_at)
                VALUES (999, 'enrollment', 'challenge', '2030-01-01 00:00:00')",
        );
    }

    public function testRejectsUnsupportedPurpose(): void
    {
        $pdo = $this->createMigratedConnection();
        $pdo->exec("INSERT INTO users (email, password_hash) VALUES ('user@example.com', 'hash')");

        $this->expectException(\PDOException::class);

        $pdo->exec(
            "INSERT INTO webauthn_challenges (user_id, purpose, challenge, expires_at)
                VALUES (1, 'signup', 'challenge', '2030-01-01 00:00:00')",
        );
    }

    public function testRejectsDuplicateChallenge(): void
    {
        $pdo = $this->createMigratedConnection();
        $pdo->exec("INSERT INTO users (email, password_hash) VALUES ('user@example.com', 'hash')");
        $pdo->exec(
            "INSERT INTO webauthn_challenges (user_id, purpose, challenge, expires_at)
                VALUES (1, 'enrollment', 'duplicate-challenge', '2030-01-01 00:00:00')",
        );

        $this->expectException(\PDOException::class);

        $pdo->exec(
            "INSERT INTO webauthn_challenges (user_id, purpose, challenge, expires_at)
                VALUES (1, 'authentication', 'duplicate-challenge', '2030-01-01 00:00:00')",
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
            new CreateWebAuthnChallengesTable(),
        ]);
        $runner->run();

        return $pdo;
    }
}
