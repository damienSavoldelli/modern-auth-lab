<?php

declare(strict_types=1);

namespace ModernAuthLab\Tests\Application\User;

use ModernAuthLab\Application\User\DevUserSeeder;
use ModernAuthLab\Infrastructure\Persistence\MigrationRepository;
use ModernAuthLab\Infrastructure\Persistence\MigrationRunner;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateUsersTable;
use ModernAuthLab\Infrastructure\Persistence\UserRepository;
use ModernAuthLab\Security\Password\PasswordHasher;
use PDO;
use PHPUnit\Framework\TestCase;

final class DevUserSeederTest extends TestCase
{
    public function testCreatesDevUserWhenMissing(): void
    {
        $passwords = new PasswordHasher();
        $users = new UserRepository($this->createMigratedConnection());
        $seeder = new DevUserSeeder($users, $passwords);

        $result = $seeder->seed();

        self::assertTrue($result->created);
        self::assertSame(DevUserSeeder::EMAIL, $result->user->email);
        self::assertTrue($passwords->verify(DevUserSeeder::PASSWORD, $result->user->passwordHash));
    }

    public function testDoesNotOverwriteExistingDevUser(): void
    {
        $passwords = new PasswordHasher();
        $users = new UserRepository($this->createMigratedConnection());
        $existingUser = $users->create(DevUserSeeder::EMAIL, $passwords->hash('existing-password'));
        $seeder = new DevUserSeeder($users, $passwords);

        $result = $seeder->seed();

        self::assertFalse($result->created);
        self::assertSame($existingUser->id, $result->user->id);
        self::assertTrue($passwords->verify('existing-password', $result->user->passwordHash));
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
