<?php

declare(strict_types=1);

namespace ModernAuthLab\Tests\Application\Totp;

use ModernAuthLab\Application\Totp\TotpRecoveryCodeService;
use ModernAuthLab\Infrastructure\Persistence\MigrationRepository;
use ModernAuthLab\Infrastructure\Persistence\MigrationRunner;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateUsersTable;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateUserTotpRecoveryCodesTable;
use ModernAuthLab\Infrastructure\Persistence\UserRepository;
use ModernAuthLab\Infrastructure\Persistence\UserTotpRecoveryCodeRepository;
use ModernAuthLab\Security\Totp\TotpRecoveryCodeGenerator;
use ModernAuthLab\Security\Totp\TotpRecoveryCodeHasher;
use PDO;
use PHPUnit\Framework\TestCase;

final class TotpRecoveryCodeServiceTest extends TestCase
{
    public function testGeneratesPlainCodesAndStoresOnlyHashes(): void
    {
        $pdo = $this->createMigratedConnection();
        $user = (new UserRepository($pdo))->create('user@example.com', 'password-hash');
        $repository = new UserTotpRecoveryCodeRepository($pdo);
        $hasher = new TotpRecoveryCodeHasher();
        $service = new TotpRecoveryCodeService($repository, new TotpRecoveryCodeGenerator(), $hasher);

        $result = $service->generateForUser($user->id, 4);
        $storedCodes = $repository->findActiveByUserId($user->id);

        self::assertCount(4, $result->plainCodes);
        self::assertCount(4, $result->records);
        self::assertCount(4, $storedCodes);

        foreach ($result->plainCodes as $index => $plainCode) {
            self::assertNotSame($plainCode, $storedCodes[$index]->codeHash);
            self::assertTrue($hasher->verify($plainCode, $storedCodes[$index]->codeHash));
        }
    }

    public function testGeneratingNewSetRevokesPreviousActiveCodes(): void
    {
        $pdo = $this->createMigratedConnection();
        $user = (new UserRepository($pdo))->create('user@example.com', 'password-hash');
        $repository = new UserTotpRecoveryCodeRepository($pdo);
        $service = new TotpRecoveryCodeService(
            $repository,
            new TotpRecoveryCodeGenerator(),
            new TotpRecoveryCodeHasher(),
        );

        $first = $service->generateForUser($user->id, 2);
        $second = $service->generateForUser($user->id, 3);
        $activeCodes = $repository->findActiveByUserId($user->id);

        self::assertCount(2, $first->plainCodes);
        self::assertCount(3, $second->plainCodes);
        self::assertCount(3, $activeCodes);
        self::assertSame($second->records[0]->id, $activeCodes[0]->id);
    }

    public function testVerifiesAndConsumesActiveRecoveryCode(): void
    {
        $pdo = $this->createMigratedConnection();
        $user = (new UserRepository($pdo))->create('user@example.com', 'password-hash');
        $repository = new UserTotpRecoveryCodeRepository($pdo);
        $service = new TotpRecoveryCodeService(
            $repository,
            new TotpRecoveryCodeGenerator(),
            new TotpRecoveryCodeHasher(),
        );
        $generated = $service->generateForUser($user->id, 2);

        $result = $service->verifyAndConsume($user->id, $generated->plainCodes[0]);
        $secondAttempt = $service->verifyAndConsume($user->id, $generated->plainCodes[0]);
        $activeCodes = $repository->findActiveByUserId($user->id);

        self::assertTrue($result->success);
        self::assertSame($generated->records[0]->id, $result->recoveryCodeId);
        self::assertFalse($secondAttempt->success);
        self::assertNull($secondAttempt->recoveryCodeId);
        self::assertCount(1, $activeCodes);
        self::assertSame($generated->records[1]->id, $activeCodes[0]->id);
    }

    public function testRejectsInvalidRecoveryCodeWithoutConsumingActiveCodes(): void
    {
        $pdo = $this->createMigratedConnection();
        $user = (new UserRepository($pdo))->create('user@example.com', 'password-hash');
        $repository = new UserTotpRecoveryCodeRepository($pdo);
        $service = new TotpRecoveryCodeService(
            $repository,
            new TotpRecoveryCodeGenerator(),
            new TotpRecoveryCodeHasher(),
        );
        $service->generateForUser($user->id, 2);

        $result = $service->verifyAndConsume($user->id, 'INVALID-CODE');

        self::assertFalse($result->success);
        self::assertNull($result->recoveryCodeId);
        self::assertCount(2, $repository->findActiveByUserId($user->id));
    }

    public function testRejectsRecoveryCodeOwnedByAnotherUser(): void
    {
        $pdo = $this->createMigratedConnection();
        $users = new UserRepository($pdo);
        $user = $users->create('user@example.com', 'password-hash');
        $otherUser = $users->create('other@example.com', 'password-hash');
        $repository = new UserTotpRecoveryCodeRepository($pdo);
        $service = new TotpRecoveryCodeService(
            $repository,
            new TotpRecoveryCodeGenerator(),
            new TotpRecoveryCodeHasher(),
        );
        $generated = $service->generateForUser($user->id, 1);

        $result = $service->verifyAndConsume($otherUser->id, $generated->plainCodes[0]);

        self::assertFalse($result->success);
        self::assertNull($result->recoveryCodeId);
        self::assertCount(1, $repository->findActiveByUserId($user->id));
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
