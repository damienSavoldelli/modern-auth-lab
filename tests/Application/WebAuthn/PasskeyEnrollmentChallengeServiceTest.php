<?php

declare(strict_types=1);

namespace ModernAuthLab\Tests\Application\WebAuthn;

use ModernAuthLab\Application\WebAuthn\PasskeyEnrollmentChallengeService;
use ModernAuthLab\Infrastructure\Persistence\MigrationRepository;
use ModernAuthLab\Infrastructure\Persistence\MigrationRunner;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateUserPasskeyCredentialsTable;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateUsersTable;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateWebAuthnChallengesTable;
use ModernAuthLab\Infrastructure\Persistence\UserPasskeyCredentialRepository;
use ModernAuthLab\Infrastructure\Persistence\UserRepository;
use ModernAuthLab\Infrastructure\Persistence\WebAuthnChallengeRepository;
use ModernAuthLab\Security\WebAuthn\Base64Url;
use ModernAuthLab\Security\WebAuthn\WebAuthnConfig;
use PDO;
use PHPUnit\Framework\TestCase;

final class PasskeyEnrollmentChallengeServiceTest extends TestCase
{
    public function testStartsEnrollmentChallengeForUser(): void
    {
        $pdo = $this->createMigratedConnection();
        $user = (new UserRepository($pdo))->create('user@example.com', 'password-hash');
        $challenges = new WebAuthnChallengeRepository($pdo);
        $credentials = new UserPasskeyCredentialRepository($pdo);
        $service = new PasskeyEnrollmentChallengeService(
            new WebAuthnConfig('127.0.0.1', 'Modern Auth Lab', ['http://127.0.0.1:8080'], 300, 60_000, 'preferred'),
            $challenges,
            $credentials,
        );

        $result = $service->start($user);
        $options = $result->publicKeyOptions;

        self::assertSame($user->id, $result->challenge->userId);
        self::assertSame('enrollment', $result->challenge->purpose);
        self::assertSame($result->challenge->challenge, $options['challenge']);
        self::assertNotNull($challenges->findUnconsumed($user->id, 'enrollment', $result->challenge->challenge));
        self::assertSame('127.0.0.1', $options['rp']['id']);
        self::assertSame('Modern Auth Lab', $options['rp']['name']);
        self::assertSame(Base64Url::encode(sprintf('user:%d', $user->id)), $options['user']['id']);
        self::assertSame('user@example.com', $options['user']['name']);
        self::assertSame('user@example.com', $options['user']['displayName']);
        self::assertSame('none', $options['attestation']);
        self::assertSame('preferred', $options['authenticatorSelection']['userVerification']);
        self::assertSame('preferred', $options['authenticatorSelection']['residentKey']);
        self::assertSame([], $options['excludeCredentials']);
    }

    public function testExcludesExistingActiveCredentials(): void
    {
        $pdo = $this->createMigratedConnection();
        $user = (new UserRepository($pdo))->create('user@example.com', 'password-hash');
        $credentials = new UserPasskeyCredentialRepository($pdo);
        $credentials->createActive($user->id, 'existing-credential', 'public-key', 0, 'YubiKey', ['usb']);
        $service = new PasskeyEnrollmentChallengeService(
            WebAuthnConfig::fromEnvironment([]),
            new WebAuthnChallengeRepository($pdo),
            $credentials,
        );

        $result = $service->start($user);

        self::assertSame(
            [
                [
                    'id' => 'existing-credential',
                    'type' => 'public-key',
                    'transports' => ['usb'],
                ],
            ],
            $result->publicKeyOptions['excludeCredentials'],
        );
    }

    private function createMigratedConnection(): PDO
    {
        $pdo = new PDO('sqlite::memory:');
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
        $pdo->exec('PRAGMA foreign_keys = ON');

        $runner = new MigrationRunner($pdo, new MigrationRepository($pdo), [
            new CreateUsersTable(),
            new CreateUserPasskeyCredentialsTable(),
            new CreateWebAuthnChallengesTable(),
        ]);
        $runner->run();

        return $pdo;
    }
}
