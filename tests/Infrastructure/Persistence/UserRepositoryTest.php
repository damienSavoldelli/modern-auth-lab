<?php

declare(strict_types=1);

namespace ModernAuthLab\Tests\Infrastructure\Persistence;

use ModernAuthLab\Infrastructure\Persistence\MigrationRepository;
use ModernAuthLab\Infrastructure\Persistence\MigrationRunner;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateUsersTable;
use ModernAuthLab\Infrastructure\Persistence\UserRepository;
use PDO;
use PHPUnit\Framework\TestCase;

final class UserRepositoryTest extends TestCase
{
    public function testCreatesAndFindsUserByEmail(): void
    {
        $repository = new UserRepository($this->createMigratedConnection());

        $createdUser = $repository->create('user@example.com', 'password-hash');
        $foundUser = $repository->findByEmail('user@example.com');

        self::assertNotNull($foundUser);
        self::assertSame($createdUser->id, $foundUser->id);
        self::assertSame('user@example.com', $foundUser->email);
        self::assertSame('password-hash', $foundUser->passwordHash);
        self::assertNotSame('', $foundUser->createdAt);
        self::assertNotSame('', $foundUser->updatedAt);
    }

    public function testReturnsNullWhenUserDoesNotExist(): void
    {
        $repository = new UserRepository($this->createMigratedConnection());

        self::assertNull($repository->findByEmail('missing@example.com'));
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
