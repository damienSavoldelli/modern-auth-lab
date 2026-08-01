<?php

declare(strict_types=1);

namespace ModernAuthLab\Tests\Application\Totp;

use ModernAuthLab\Application\Totp\TotpDisableService;
use ModernAuthLab\Application\Totp\TotpEnrollmentService;
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

final class TotpDisableServiceTest extends TestCase
{
    public function testDisablesActiveTotpCredentialWithValidCode(): void
    {
        $pdo = $this->createMigratedConnection();
        $user = (new UserRepository($pdo))->create('user@example.com', 'password-hash');
        $credentials = new UserTotpCredentialRepository($pdo);
        $secretProtector = new TotpSecretProtector(str_repeat('a', 32), 'local');
        $secret = $this->activateTotp($credentials, $secretProtector, $user->id, $user->email);
        $code = (new TotpGenerator())->generate($secret, 90);
        $service = new TotpDisableService($credentials, $secretProtector);

        $disabled = $service->disable($user->id, $code, 90);

        self::assertTrue($disabled);
        self::assertNull($credentials->findActiveByUserId($user->id));
    }

    public function testRejectsInvalidCodeWithoutRevokingCredential(): void
    {
        $pdo = $this->createMigratedConnection();
        $user = (new UserRepository($pdo))->create('user@example.com', 'password-hash');
        $credentials = new UserTotpCredentialRepository($pdo);
        $secretProtector = new TotpSecretProtector(str_repeat('a', 32), 'local');
        $this->activateTotp($credentials, $secretProtector, $user->id, $user->email);
        $service = new TotpDisableService($credentials, $secretProtector);

        $disabled = $service->disable($user->id, '000000', 90);

        self::assertFalse($disabled);
        self::assertNotNull($credentials->findActiveByUserId($user->id));
    }

    public function testRejectsAlreadyAcceptedTimeStepWithoutRevokingCredential(): void
    {
        $pdo = $this->createMigratedConnection();
        $user = (new UserRepository($pdo))->create('user@example.com', 'password-hash');
        $credentials = new UserTotpCredentialRepository($pdo);
        $secretProtector = new TotpSecretProtector(str_repeat('a', 32), 'local');
        $secret = $this->activateTotp($credentials, $secretProtector, $user->id, $user->email);
        $active = $credentials->findActiveByUserId($user->id);
        self::assertNotNull($active);
        $credentials->recordLastUsedTimeStep($active->id, 3);
        $code = (new TotpGenerator())->generate($secret, 90);
        $service = new TotpDisableService($credentials, $secretProtector);

        $disabled = $service->disable($user->id, $code, 90);

        self::assertFalse($disabled);
        self::assertNotNull($credentials->findActiveByUserId($user->id));
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
