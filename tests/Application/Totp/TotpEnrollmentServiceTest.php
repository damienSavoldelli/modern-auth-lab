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
use ModernAuthLab\Security\Totp\TotpGenerator;
use ModernAuthLab\Security\Totp\TotpSecret;
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

    public function testRevokesExpiredPendingEnrollmentAndCreatesReplacement(): void
    {
        $pdo = $this->createMigratedConnection();
        $user = (new UserRepository($pdo))->create('user@example.com', 'password-hash');
        $credentials = new UserTotpCredentialRepository($pdo);
        $now = strtotime('2026-08-01 12:00:00 UTC');
        self::assertIsInt($now);
        $service = new TotpEnrollmentService(
            $credentials,
            new TotpSecretProtector(str_repeat('a', 32), 'local'),
            pendingLifetimeSeconds: 1800,
            now: static fn(): int => $now,
        );
        $first = $service->start($user->id, $user->email);
        $this->moveCredentialCreatedAt($pdo, $first->credential->id, '2026-08-01 11:00:00');

        $second = $service->start($user->id, $user->email);

        self::assertTrue($second->created);
        self::assertNotSame($first->credential->id, $second->credential->id);
        self::assertSame('revoked', $this->credentialStatus($pdo, $first->credential->id));
        self::assertNotNull($this->credentialRevokedAt($pdo, $first->credential->id));
        self::assertSame($second->credential->id, $credentials->findPendingByUserId($user->id)?->id);
    }

    public function testRejectsConfirmationForExpiredPendingEnrollment(): void
    {
        $pdo = $this->createMigratedConnection();
        $user = (new UserRepository($pdo))->create('user@example.com', 'password-hash');
        $credentials = new UserTotpCredentialRepository($pdo);
        $now = strtotime('2026-08-01 12:00:00 UTC');
        self::assertIsInt($now);
        $service = new TotpEnrollmentService(
            $credentials,
            new TotpSecretProtector(str_repeat('a', 32), 'local'),
            pendingLifetimeSeconds: 1800,
            now: static fn(): int => $now,
        );
        $pending = $service->start($user->id, $user->email);
        $code = $this->codeFromProvisioningSecret($pending->secretBase32, $now);
        $this->moveCredentialCreatedAt($pdo, $pending->credential->id, '2026-08-01 11:00:00');

        $confirmed = $service->confirm($user->id, $code, $now);

        self::assertFalse($confirmed);
        self::assertSame('revoked', $this->credentialStatus($pdo, $pending->credential->id));
        self::assertNull($credentials->findPendingByUserId($user->id));
        self::assertNull($credentials->findActiveByUserId($user->id));
    }

    public function testRejectsInvalidPendingEnrollmentLifetime(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('TOTP pending enrollment lifetime must be greater than zero.');

        new TotpEnrollmentService(
            new UserTotpCredentialRepository($this->createMigratedConnection()),
            new TotpSecretProtector(str_repeat('a', 32), 'local'),
            pendingLifetimeSeconds: 0,
        );
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

    public function testConfirmsPendingEnrollmentWithValidCode(): void
    {
        $pdo = $this->createMigratedConnection();
        $user = (new UserRepository($pdo))->create('user@example.com', 'password-hash');
        $credentials = new UserTotpCredentialRepository($pdo);
        $service = new TotpEnrollmentService($credentials, new TotpSecretProtector(str_repeat('a', 32), 'local'));
        $pending = $service->start($user->id, $user->email);
        $code = $this->codeFromProvisioningSecret($pending->secretBase32, 59);

        $confirmed = $service->confirm($user->id, $code, 59);
        $activeCredential = $credentials->findActiveByUserId($user->id);

        self::assertTrue($confirmed);
        self::assertNotNull($activeCredential);
        self::assertSame($pending->credential->id, $activeCredential->id);
        self::assertSame(1, $activeCredential->lastUsedTimeStep);
    }

    public function testRejectsInvalidConfirmationCode(): void
    {
        $pdo = $this->createMigratedConnection();
        $user = (new UserRepository($pdo))->create('user@example.com', 'password-hash');
        $credentials = new UserTotpCredentialRepository($pdo);
        $service = new TotpEnrollmentService($credentials, new TotpSecretProtector(str_repeat('a', 32), 'local'));
        $service->start($user->id, $user->email);

        $confirmed = $service->confirm($user->id, '000000', 59);

        self::assertFalse($confirmed);
        self::assertNotNull($credentials->findPendingByUserId($user->id));
        self::assertNull($credentials->findActiveByUserId($user->id));
    }

    public function testRejectsConfirmationWithoutPendingCredential(): void
    {
        $pdo = $this->createMigratedConnection();
        $user = (new UserRepository($pdo))->create('user@example.com', 'password-hash');
        $service = new TotpEnrollmentService(
            new UserTotpCredentialRepository($pdo),
            new TotpSecretProtector(str_repeat('a', 32), 'local'),
        );

        self::assertFalse($service->confirm($user->id, '000000', 59));
    }

    private function codeFromProvisioningSecret(string $base32Secret, int $timestamp): string
    {
        $secret = TotpSecret::fromBase32($base32Secret);

        return (new TotpGenerator())->generate($secret, $timestamp);
    }

    private function moveCredentialCreatedAt(PDO $pdo, int $credentialId, string $createdAt): void
    {
        $statement = $pdo->prepare(
            'UPDATE user_totp_credentials
                SET created_at = :created_at,
                    updated_at = :created_at
                WHERE id = :id',
        );
        $statement->execute([
            'id' => $credentialId,
            'created_at' => $createdAt,
        ]);
    }

    private function credentialStatus(PDO $pdo, int $credentialId): string
    {
        $statement = $pdo->prepare('SELECT status FROM user_totp_credentials WHERE id = :id');
        $statement->execute(['id' => $credentialId]);

        return (string) $statement->fetchColumn();
    }

    private function credentialRevokedAt(PDO $pdo, int $credentialId): ?string
    {
        $statement = $pdo->prepare('SELECT revoked_at FROM user_totp_credentials WHERE id = :id');
        $statement->execute(['id' => $credentialId]);
        $value = $statement->fetchColumn();

        return is_string($value) ? $value : null;
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
