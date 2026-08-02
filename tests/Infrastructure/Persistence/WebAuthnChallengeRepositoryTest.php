<?php

declare(strict_types=1);

namespace ModernAuthLab\Tests\Infrastructure\Persistence;

use DateTimeImmutable;
use ModernAuthLab\Infrastructure\Persistence\MigrationRepository;
use ModernAuthLab\Infrastructure\Persistence\MigrationRunner;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateUsersTable;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateWebAuthnChallengesTable;
use ModernAuthLab\Infrastructure\Persistence\UserRepository;
use ModernAuthLab\Infrastructure\Persistence\WebAuthnChallengeRepository;
use PDO;
use PHPUnit\Framework\TestCase;

final class WebAuthnChallengeRepositoryTest extends TestCase
{
    public function testCreatesAndFindsUnconsumedChallenge(): void
    {
        $pdo = $this->createMigratedConnection();
        $user = (new UserRepository($pdo))->create('user@example.com', 'password-hash');
        $repository = new WebAuthnChallengeRepository($pdo);

        $created = $repository->create(
            $user->id,
            'enrollment',
            'challenge',
            new DateTimeImmutable('2030-01-01 00:00:00'),
        );
        $found = $repository->findUnconsumed($user->id, 'enrollment', 'challenge');

        self::assertNotNull($found);
        self::assertSame($created->id, $found->id);
        self::assertSame($user->id, $found->userId);
        self::assertSame('enrollment', $found->purpose);
        self::assertSame('challenge', $found->challenge);
        self::assertSame('2030-01-01 00:00:00', $found->expiresAt);
        self::assertNull($found->consumedAt);
    }

    public function testConsumesChallenge(): void
    {
        $pdo = $this->createMigratedConnection();
        $user = (new UserRepository($pdo))->create('user@example.com', 'password-hash');
        $repository = new WebAuthnChallengeRepository($pdo);
        $challenge = $repository->create($user->id, 'enrollment', 'challenge', new DateTimeImmutable('2030-01-01 00:00:00'));

        $consumed = $repository->consume($challenge->id);

        self::assertNotNull($consumed->consumedAt);
        self::assertNull($repository->findUnconsumed($user->id, 'enrollment', 'challenge'));
    }

    public function testReturnsNullWhenChallengeDoesNotMatch(): void
    {
        $pdo = $this->createMigratedConnection();
        $user = (new UserRepository($pdo))->create('user@example.com', 'password-hash');
        $repository = new WebAuthnChallengeRepository($pdo);

        self::assertNull($repository->findUnconsumed($user->id, 'enrollment', 'missing'));
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
