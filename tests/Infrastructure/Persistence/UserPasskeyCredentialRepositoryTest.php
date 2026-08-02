<?php

declare(strict_types=1);

namespace ModernAuthLab\Tests\Infrastructure\Persistence;

use ModernAuthLab\Infrastructure\Persistence\MigrationRepository;
use ModernAuthLab\Infrastructure\Persistence\MigrationRunner;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateUserPasskeyCredentialsTable;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateUsersTable;
use ModernAuthLab\Infrastructure\Persistence\UserPasskeyCredentialRepository;
use ModernAuthLab\Infrastructure\Persistence\UserRepository;
use PDO;
use PHPUnit\Framework\TestCase;

final class UserPasskeyCredentialRepositoryTest extends TestCase
{
    public function testCreatesAndFindsActiveCredential(): void
    {
        $pdo = $this->createMigratedConnection();
        $user = (new UserRepository($pdo))->create('user@example.com', 'password-hash');
        $repository = new UserPasskeyCredentialRepository($pdo);

        $created = $repository->createActive(
            $user->id,
            'credential-id',
            'public-key',
            42,
            'MacBook Touch ID',
            ['internal', 'hybrid'],
            'none',
            '00000000-0000-0000-0000-000000000000',
        );
        $found = $repository->findActiveByCredentialId('credential-id');

        self::assertNotNull($found);
        self::assertSame($created->id, $found->id);
        self::assertSame($user->id, $found->userId);
        self::assertSame('credential-id', $found->credentialId);
        self::assertSame('public-key', $found->publicKey);
        self::assertSame(42, $found->signCount);
        self::assertSame('MacBook Touch ID', $found->name);
        self::assertSame(['internal', 'hybrid'], $found->transports);
        self::assertSame('none', $found->attestationType);
        self::assertSame('00000000-0000-0000-0000-000000000000', $found->aaguid);
        self::assertSame('active', $found->status);
        self::assertNull($found->lastUsedAt);
        self::assertNull($found->revokedAt);
    }

    public function testAllowsMultipleActiveCredentialsForOneUser(): void
    {
        $pdo = $this->createMigratedConnection();
        $user = (new UserRepository($pdo))->create('user@example.com', 'password-hash');
        $repository = new UserPasskeyCredentialRepository($pdo);

        $first = $repository->createActive($user->id, 'credential-id-1', 'public-key-1', 0, 'MacBook');
        $second = $repository->createActive($user->id, 'credential-id-2', 'public-key-2', 0, 'YubiKey', ['usb']);

        $activeCredentials = $repository->findActiveByUserId($user->id);

        self::assertCount(2, $activeCredentials);
        self::assertSame([$first->id, $second->id], array_map(static fn($credential): int => $credential->id, $activeCredentials));
    }

    public function testRecordsSuccessfulUse(): void
    {
        $pdo = $this->createMigratedConnection();
        $user = (new UserRepository($pdo))->create('user@example.com', 'password-hash');
        $repository = new UserPasskeyCredentialRepository($pdo);
        $credential = $repository->createActive($user->id, 'credential-id', 'public-key', 0, 'MacBook');

        $updated = $repository->recordSuccessfulUse($credential->id, 10);

        self::assertSame(10, $updated->signCount);
        self::assertNotNull($updated->lastUsedAt);
    }

    public function testRevokesCredential(): void
    {
        $pdo = $this->createMigratedConnection();
        $user = (new UserRepository($pdo))->create('user@example.com', 'password-hash');
        $repository = new UserPasskeyCredentialRepository($pdo);
        $credential = $repository->createActive($user->id, 'credential-id', 'public-key', 0, 'MacBook');

        $revoked = $repository->revoke($credential->id);

        self::assertSame('revoked', $revoked->status);
        self::assertNotNull($revoked->revokedAt);
        self::assertNull($repository->findActiveByCredentialId('credential-id'));
        self::assertSame([], $repository->findActiveByUserId($user->id));
    }

    public function testReturnsNullWhenNoCredentialExists(): void
    {
        $repository = new UserPasskeyCredentialRepository($this->createMigratedConnection());

        self::assertNull($repository->findActiveByCredentialId('missing-credential'));
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
