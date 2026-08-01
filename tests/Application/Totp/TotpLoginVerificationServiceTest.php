<?php

declare(strict_types=1);

namespace ModernAuthLab\Tests\Application\Totp;

use ModernAuthLab\Application\Totp\TotpEnrollmentService;
use ModernAuthLab\Application\Totp\TotpLoginVerificationService;
use ModernAuthLab\Infrastructure\Persistence\MigrationRepository;
use ModernAuthLab\Infrastructure\Persistence\MigrationRunner;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateUsersTable;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateUserTotpCredentialsTable;
use ModernAuthLab\Infrastructure\Persistence\UserRepository;
use ModernAuthLab\Infrastructure\Persistence\UserTotpCredentialRepository;
use ModernAuthLab\Security\Totp\TotpGenerator;
use ModernAuthLab\Security\Totp\TotpSecret;
use ModernAuthLab\Security\Totp\TotpSecretProtector;
use PDO;
use PHPUnit\Framework\TestCase;

final class TotpLoginVerificationServiceTest extends TestCase
{
    public function testVerifiesCodeForActiveTotpCredential(): void
    {
        $pdo = $this->createMigratedConnection();
        $user = (new UserRepository($pdo))->create('user@example.com', 'password-hash');
        $credentials = new UserTotpCredentialRepository($pdo);
        $secretProtector = new TotpSecretProtector(str_repeat('a', 32), 'local');
        $secret = $this->activateTotp($credentials, $secretProtector, $user->id, $user->email);
        $code = (new TotpGenerator())->generate($secret, 90);
        $service = new TotpLoginVerificationService($credentials, $secretProtector);

        $result = $service->verify($user->id, $code, 90);
        $activeCredential = $credentials->findActiveByUserId($user->id);

        self::assertTrue($result->success);
        self::assertSame(3, $result->timeStep);
        self::assertNotNull($activeCredential);
        self::assertSame(3, $activeCredential->lastUsedTimeStep);
    }

    public function testRejectsCodeWhenNoActiveTotpCredentialExists(): void
    {
        $pdo = $this->createMigratedConnection();
        $user = (new UserRepository($pdo))->create('user@example.com', 'password-hash');
        $service = new TotpLoginVerificationService(
            new UserTotpCredentialRepository($pdo),
            new TotpSecretProtector(str_repeat('a', 32), 'local'),
        );

        $result = $service->verify($user->id, '123456', 90);

        self::assertFalse($result->success);
        self::assertNull($result->timeStep);
    }

    public function testRejectsInvalidCodeForActiveTotpCredential(): void
    {
        $pdo = $this->createMigratedConnection();
        $user = (new UserRepository($pdo))->create('user@example.com', 'password-hash');
        $credentials = new UserTotpCredentialRepository($pdo);
        $secretProtector = new TotpSecretProtector(str_repeat('a', 32), 'local');
        $this->activateTotp($credentials, $secretProtector, $user->id, $user->email);
        $service = new TotpLoginVerificationService($credentials, $secretProtector);

        $result = $service->verify($user->id, '000000', 90);
        $activeCredential = $credentials->findActiveByUserId($user->id);

        self::assertFalse($result->success);
        self::assertNull($result->timeStep);
        self::assertNotNull($activeCredential);
        self::assertSame(1, $activeCredential->lastUsedTimeStep);
    }

    public function testRejectsAlreadyAcceptedTimeStep(): void
    {
        $pdo = $this->createMigratedConnection();
        $user = (new UserRepository($pdo))->create('user@example.com', 'password-hash');
        $credentials = new UserTotpCredentialRepository($pdo);
        $secretProtector = new TotpSecretProtector(str_repeat('a', 32), 'local');
        $secret = $this->activateTotp($credentials, $secretProtector, $user->id, $user->email);
        $code = (new TotpGenerator())->generate($secret, 90);
        $service = new TotpLoginVerificationService($credentials, $secretProtector);

        $firstResult = $service->verify($user->id, $code, 90);
        $secondResult = $service->verify($user->id, $code, 90);
        $activeCredential = $credentials->findActiveByUserId($user->id);

        self::assertTrue($firstResult->success);
        self::assertFalse($secondResult->success);
        self::assertNull($secondResult->timeStep);
        self::assertNotNull($activeCredential);
        self::assertSame(3, $activeCredential->lastUsedTimeStep);
    }

    public function testRejectsOlderAcceptedTimeStepInsideVerificationWindow(): void
    {
        $pdo = $this->createMigratedConnection();
        $user = (new UserRepository($pdo))->create('user@example.com', 'password-hash');
        $credentials = new UserTotpCredentialRepository($pdo);
        $secretProtector = new TotpSecretProtector(str_repeat('a', 32), 'local');
        $secret = $this->activateTotp($credentials, $secretProtector, $user->id, $user->email);
        $service = new TotpLoginVerificationService($credentials, $secretProtector);
        $currentCode = (new TotpGenerator())->generate($secret, 90);
        $previousCode = (new TotpGenerator())->generate($secret, 60);

        $firstResult = $service->verify($user->id, $currentCode, 90);
        $olderResult = $service->verify($user->id, $previousCode, 90);
        $activeCredential = $credentials->findActiveByUserId($user->id);

        self::assertTrue($firstResult->success);
        self::assertFalse($olderResult->success);
        self::assertNull($olderResult->timeStep);
        self::assertNotNull($activeCredential);
        self::assertSame(3, $activeCredential->lastUsedTimeStep);
    }

    private function activateTotp(
        UserTotpCredentialRepository $credentials,
        TotpSecretProtector $secretProtector,
        int $userId,
        string $email,
    ): TotpSecret {
        $enrollment = new TotpEnrollmentService($credentials, $secretProtector);
        $pending = $enrollment->start($userId, $email);
        $secret = TotpSecret::fromBase32($pending->secretBase32);
        $code = (new TotpGenerator())->generate($secret, 59);

        self::assertTrue($enrollment->confirm($userId, $code, 59));

        return $secret;
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
