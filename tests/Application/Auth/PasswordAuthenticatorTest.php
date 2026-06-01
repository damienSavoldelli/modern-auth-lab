<?php

declare(strict_types=1);

namespace ModernAuthLab\Tests\Application\Auth;

use ModernAuthLab\Application\Auth\PasswordAuthenticator;
use ModernAuthLab\Infrastructure\Persistence\MigrationRepository;
use ModernAuthLab\Infrastructure\Persistence\MigrationRunner;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateUsersTable;
use ModernAuthLab\Infrastructure\Persistence\UserRepository;
use ModernAuthLab\Security\Password\PasswordHasher;
use PDO;
use PHPUnit\Framework\TestCase;

final class PasswordAuthenticatorTest extends TestCase
{
    public function testAuthenticatesUserWithValidPassword(): void
    {
        $passwords = new PasswordHasher();
        $users = new UserRepository($this->createMigratedConnection());
        $createdUser = $users->create('user@example.com', $passwords->hash('correct password'));
        $authenticator = new PasswordAuthenticator($users, $passwords);

        $result = $authenticator->authenticate('user@example.com', 'correct password');

        self::assertTrue($result->success);
        self::assertSame($createdUser->id, $result->user?->id);
    }

    public function testRejectsInvalidPassword(): void
    {
        $passwords = new PasswordHasher();
        $users = new UserRepository($this->createMigratedConnection());
        $users->create('user@example.com', $passwords->hash('correct password'));
        $authenticator = new PasswordAuthenticator($users, $passwords);

        $result = $authenticator->authenticate('user@example.com', 'wrong password');

        self::assertFalse($result->success);
        self::assertNull($result->user);
    }

    public function testRejectsMissingUser(): void
    {
        $passwords = new PasswordHasher();
        $users = new UserRepository($this->createMigratedConnection());
        $authenticator = new PasswordAuthenticator($users, $passwords);

        $result = $authenticator->authenticate('missing@example.com', 'password');

        self::assertFalse($result->success);
        self::assertNull($result->user);
    }

    private function createMigratedConnection(): PDO
    {
        $pdo = new PDO('sqlite::memory:');
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);

        $runner = new MigrationRunner($pdo, new MigrationRepository($pdo), [new CreateUsersTable()]);
        $runner->run();

        return $pdo;
    }
}
