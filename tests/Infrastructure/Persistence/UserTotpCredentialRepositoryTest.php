<?php

declare(strict_types=1);

namespace ModernAuthLab\Tests\Infrastructure\Persistence;

use ModernAuthLab\Infrastructure\Persistence\MigrationRepository;
use ModernAuthLab\Infrastructure\Persistence\MigrationRunner;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateUsersTable;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateUserTotpCredentialsTable;
use ModernAuthLab\Infrastructure\Persistence\UserRepository;
use ModernAuthLab\Infrastructure\Persistence\UserTotpCredentialRepository;
use PDO;
use PHPUnit\Framework\TestCase;

final class UserTotpCredentialRepositoryTest extends TestCase
{
    public function testCreatesAndFindsPendingCredential(): void
    {
        $pdo = $this->createMigratedConnection();
        $user = (new UserRepository($pdo))->create('user@example.com', 'password-hash');
        $repository = new UserTotpCredentialRepository($pdo);

        $created = $repository->createPending(
            $user->id,
            'encrypted-secret',
            'secret-nonce',
            'local-key',
            'SHA1',
            6,
            30,
        );
        $found = $repository->findPendingByUserId($user->id);

        self::assertNotNull($found);
        self::assertSame($created->id, $found->id);
        self::assertSame($user->id, $found->userId);
        self::assertSame('encrypted-secret', $found->secretCiphertext);
        self::assertSame('secret-nonce', $found->secretNonce);
        self::assertSame('local-key', $found->secretKeyId);
        self::assertSame('SHA1', $found->algorithm);
        self::assertSame(6, $found->digits);
        self::assertSame(30, $found->period);
        self::assertSame('pending', $found->status);
        self::assertNull($found->confirmedAt);
        self::assertNull($found->lastUsedTimeStep);
        self::assertNull($found->revokedAt);
    }

    public function testConfirmsPendingCredential(): void
    {
        $pdo = $this->createMigratedConnection();
        $user = (new UserRepository($pdo))->create('user@example.com', 'password-hash');
        $repository = new UserTotpCredentialRepository($pdo);
        $pending = $repository->createPending($user->id, 'encrypted-secret', 'secret-nonce', 'local-key', 'SHA1', 6, 30);

        $confirmed = $repository->confirm($pending->id);

        self::assertSame('active', $confirmed->status);
        self::assertNotNull($confirmed->confirmedAt);
        self::assertNull($repository->findPendingByUserId($user->id));
        self::assertSame($confirmed->id, $repository->findActiveByUserId($user->id)?->id);
    }

    public function testRevokesCredential(): void
    {
        $pdo = $this->createMigratedConnection();
        $user = (new UserRepository($pdo))->create('user@example.com', 'password-hash');
        $repository = new UserTotpCredentialRepository($pdo);
        $pending = $repository->createPending($user->id, 'encrypted-secret', 'secret-nonce', 'local-key', 'SHA1', 6, 30);
        $active = $repository->confirm($pending->id);

        $revoked = $repository->revoke($active->id);

        self::assertSame('revoked', $revoked->status);
        self::assertNotNull($revoked->revokedAt);
        self::assertNull($repository->findActiveByUserId($user->id));
    }

    public function testRecordsLastUsedTimeStepOnlyWhenItMovesForward(): void
    {
        $pdo = $this->createMigratedConnection();
        $user = (new UserRepository($pdo))->create('user@example.com', 'password-hash');
        $repository = new UserTotpCredentialRepository($pdo);
        $credential = $repository->createPending($user->id, 'encrypted-secret', 'secret-nonce', 'local-key', 'SHA1', 6, 30);

        $firstUpdate = $repository->recordLastUsedTimeStep($credential->id, 100);
        $secondUpdate = $repository->recordLastUsedTimeStep($credential->id, 99);

        self::assertSame(100, $firstUpdate->lastUsedTimeStep);
        self::assertSame(100, $secondUpdate->lastUsedTimeStep);
    }

    public function testReturnsNullWhenNoCredentialExists(): void
    {
        $pdo = $this->createMigratedConnection();
        $user = (new UserRepository($pdo))->create('user@example.com', 'password-hash');
        $repository = new UserTotpCredentialRepository($pdo);

        self::assertNull($repository->findPendingByUserId($user->id));
        self::assertNull($repository->findActiveByUserId($user->id));
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
