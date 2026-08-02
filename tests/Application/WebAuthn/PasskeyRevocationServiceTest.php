<?php

declare(strict_types=1);

namespace ModernAuthLab\Tests\Application\WebAuthn;

use ModernAuthLab\Application\WebAuthn\PasskeyRevocationService;
use ModernAuthLab\Infrastructure\Persistence\MigrationRepository;
use ModernAuthLab\Infrastructure\Persistence\MigrationRunner;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateUserPasskeyCredentialsTable;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateUsersTable;
use ModernAuthLab\Infrastructure\Persistence\UserPasskeyCredentialRepository;
use ModernAuthLab\Infrastructure\Persistence\UserRepository;
use PDO;
use PHPUnit\Framework\TestCase;

final class PasskeyRevocationServiceTest extends TestCase
{
    public function testRevokesCredentialOwnedByTheUser(): void
    {
        $pdo = $this->createMigratedConnection();
        $user = (new UserRepository($pdo))->create('user@example.com', 'hash');
        $credentials = new UserPasskeyCredentialRepository($pdo);
        $stored = $credentials->createActive($user->id, 'credential-id', 'public-key', 0, 'Work');
        $service = new PasskeyRevocationService($credentials);

        $service->revoke($user->id, $stored->id);

        self::assertSame([], $credentials->findActiveByUserId($user->id));
    }

    public function testRejectsRevokingCredentialOfAnotherUser(): void
    {
        $pdo = $this->createMigratedConnection();
        $users = new UserRepository($pdo);
        $alice = $users->create('alice@example.com', 'hash');
        $bob = $users->create('bob@example.com', 'hash');
        $credentials = new UserPasskeyCredentialRepository($pdo);
        $aliceCredential = $credentials->createActive($alice->id, 'credential-id', 'public-key', 0, 'Alice');
        $service = new PasskeyRevocationService($credentials);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Passkey credential was not found for the requesting user.');

        $service->revoke($bob->id, $aliceCredential->id);
    }

    public function testRejectsRevokingUnknownCredential(): void
    {
        $pdo = $this->createMigratedConnection();
        $user = (new UserRepository($pdo))->create('user@example.com', 'hash');
        $service = new PasskeyRevocationService(new UserPasskeyCredentialRepository($pdo));

        $this->expectException(\RuntimeException::class);

        $service->revoke($user->id, 999);
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
