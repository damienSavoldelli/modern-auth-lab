<?php

declare(strict_types=1);

namespace ModernAuthLab\Tests\Infrastructure\Persistence;

use ModernAuthLab\Infrastructure\Persistence\MigrationRepository;
use ModernAuthLab\Infrastructure\Persistence\MigrationRunner;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateUsersTable;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateUserTotpRecoveryCodesTable;
use ModernAuthLab\Infrastructure\Persistence\UserRepository;
use ModernAuthLab\Infrastructure\Persistence\UserTotpRecoveryCodeRepository;
use PDO;
use PHPUnit\Framework\TestCase;

final class UserTotpRecoveryCodeRepositoryTest extends TestCase
{
    public function testCreatesAndFindsActiveRecoveryCodes(): void
    {
        $pdo = $this->createMigratedConnection();
        $user = (new UserRepository($pdo))->create('user@example.com', 'password-hash');
        $repository = new UserTotpRecoveryCodeRepository($pdo);

        $first = $repository->createActive($user->id, 'hash-one');
        $second = $repository->createActive($user->id, 'hash-two');
        $activeCodes = $repository->findActiveByUserId($user->id);

        self::assertCount(2, $activeCodes);
        self::assertSame($first->id, $activeCodes[0]->id);
        self::assertSame($second->id, $activeCodes[1]->id);
        self::assertSame($user->id, $activeCodes[0]->userId);
        self::assertSame('hash-one', $activeCodes[0]->codeHash);
        self::assertSame('active', $activeCodes[0]->status);
        self::assertNull($activeCodes[0]->usedAt);
        self::assertNull($activeCodes[0]->revokedAt);
    }

    public function testMarksActiveRecoveryCodeAsUsed(): void
    {
        $pdo = $this->createMigratedConnection();
        $user = (new UserRepository($pdo))->create('user@example.com', 'password-hash');
        $repository = new UserTotpRecoveryCodeRepository($pdo);
        $code = $repository->createActive($user->id, 'hash-one');

        $used = $repository->markUsed($code->id);

        self::assertSame('used', $used->status);
        self::assertNotNull($used->usedAt);
        self::assertNull($used->revokedAt);
        self::assertSame([], $repository->findActiveByUserId($user->id));
    }

    public function testRevokesActiveRecoveryCodesForUser(): void
    {
        $pdo = $this->createMigratedConnection();
        $users = new UserRepository($pdo);
        $user = $users->create('user@example.com', 'password-hash');
        $otherUser = $users->create('other@example.com', 'password-hash');
        $repository = new UserTotpRecoveryCodeRepository($pdo);
        $repository->createActive($user->id, 'hash-one');
        $repository->createActive($user->id, 'hash-two');
        $repository->createActive($otherUser->id, 'hash-three');

        $repository->revokeActiveByUserId($user->id);

        self::assertSame([], $repository->findActiveByUserId($user->id));
        self::assertCount(1, $repository->findActiveByUserId($otherUser->id));
    }

    public function testReturnsEmptyListWhenUserHasNoActiveRecoveryCodes(): void
    {
        $pdo = $this->createMigratedConnection();
        $user = (new UserRepository($pdo))->create('user@example.com', 'password-hash');
        $repository = new UserTotpRecoveryCodeRepository($pdo);

        self::assertSame([], $repository->findActiveByUserId($user->id));
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
