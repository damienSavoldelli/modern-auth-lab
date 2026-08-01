<?php

declare(strict_types=1);

namespace ModernAuthLab\Tests\Application\Totp;

use ModernAuthLab\Application\Totp\TotpEnrollmentService;
use ModernAuthLab\Infrastructure\Persistence\MigrationRepository;
use ModernAuthLab\Infrastructure\Persistence\MigrationRunner;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateUsersTable;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateUserTotpCredentialsTable;
use ModernAuthLab\Infrastructure\Persistence\UserRepository;
use ModernAuthLab\Infrastructure\Persistence\UserTotpCredentialRepository;
use ModernAuthLab\Security\Totp\TotpSecretProtector;
use PDO;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class TotpEnrollmentServiceTest extends TestCase
{
    public function testStartsPendingEnrollment(): void
    {
        $pdo = $this->createMigratedConnection();
        $user = (new UserRepository($pdo))->create('user@example.com', 'password-hash');
        $credentials = new UserTotpCredentialRepository($pdo);
        $service = new TotpEnrollmentService($credentials, new TotpSecretProtector(str_repeat('a', 32), 'local'));

        $result = $service->start($user->id, $user->email);

        self::assertTrue($result->created);
        self::assertSame('pending', $result->credential->status);
        self::assertSame('SHA1', $result->credential->algorithm);
        self::assertSame(6, $result->credential->digits);
        self::assertSame(30, $result->credential->period);
        self::assertStringStartsWith('otpauth://totp/Modern%20Auth%20Lab:user%40example.com?', $result->provisioningUri);
        self::assertStringContainsString('issuer=Modern%20Auth%20Lab', $result->provisioningUri);
        self::assertMatchesRegularExpression('/^[A-Z2-7]+$/', $result->secretBase32);
        self::assertNotNull($credentials->findPendingByUserId($user->id));
    }

    public function testResumesExistingPendingEnrollment(): void
    {
        $pdo = $this->createMigratedConnection();
        $user = (new UserRepository($pdo))->create('user@example.com', 'password-hash');
        $credentials = new UserTotpCredentialRepository($pdo);
        $service = new TotpEnrollmentService($credentials, new TotpSecretProtector(str_repeat('a', 32), 'local'));

        $first = $service->start($user->id, $user->email);
        $second = $service->start($user->id, $user->email);

        self::assertFalse($second->created);
        self::assertSame($first->credential->id, $second->credential->id);
        self::assertSame($first->provisioningUri, $second->provisioningUri);
    }

    public function testRejectsStartWhenTotpIsAlreadyActive(): void
    {
        $pdo = $this->createMigratedConnection();
        $user = (new UserRepository($pdo))->create('user@example.com', 'password-hash');
        $credentials = new UserTotpCredentialRepository($pdo);
        $service = new TotpEnrollmentService($credentials, new TotpSecretProtector(str_repeat('a', 32), 'local'));
        $pending = $service->start($user->id, $user->email);
        $credentials->confirm($pending->credential->id);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('TOTP is already active for this user.');

        $service->start($user->id, $user->email);
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
