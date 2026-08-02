<?php

declare(strict_types=1);

namespace ModernAuthLab\Tests\Application\WebAuthn;

use ModernAuthLab\Application\WebAuthn\PasskeyAuthenticationChallengeService;
use ModernAuthLab\Infrastructure\Persistence\MigrationRepository;
use ModernAuthLab\Infrastructure\Persistence\MigrationRunner;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateUserPasskeyCredentialsTable;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateUsersTable;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateWebAuthnChallengesTable;
use ModernAuthLab\Infrastructure\Persistence\UserPasskeyCredentialRepository;
use ModernAuthLab\Infrastructure\Persistence\UserRepository;
use ModernAuthLab\Infrastructure\Persistence\WebAuthnChallengeRepository;
use ModernAuthLab\Security\WebAuthn\WebAuthnConfig;
use PDO;
use PHPUnit\Framework\TestCase;

final class PasskeyAuthenticationChallengeServiceTest extends TestCase
{
    public function testStartsAuthenticationChallengeForActivePasskeys(): void
    {
        $pdo = $this->createMigratedConnection();
        $user = (new UserRepository($pdo))->create('user@example.com', 'password-hash');
        $credentials = new UserPasskeyCredentialRepository($pdo);
        $credentials->createActive($user->id, 'credential-1', 'public-key-1', 0, 'MacBook', ['internal']);
        $credentials->createActive($user->id, 'credential-2', 'public-key-2', 0, 'YubiKey', ['usb']);
        $challenges = new WebAuthnChallengeRepository($pdo);
        $service = new PasskeyAuthenticationChallengeService(
            new WebAuthnConfig('127.0.0.1', 'Modern Auth Lab', ['http://127.0.0.1:8080'], 300, 60_000, 'preferred'),
            $challenges,
            $credentials,
        );

        $result = $service->start($user);
        $options = $result->publicKeyOptions;

        self::assertSame($user->id, $result->challenge->userId);
        self::assertSame('authentication', $result->challenge->purpose);
        self::assertSame($result->challenge->challenge, $options['challenge']);
        self::assertNotNull($challenges->findUnconsumed($user->id, 'authentication', $result->challenge->challenge));
        self::assertSame('127.0.0.1', $options['rpId']);
        self::assertSame('preferred', $options['userVerification']);
        self::assertSame(60_000, $options['timeout']);
        self::assertSame(
            [
                [
                    'id' => 'credential-1',
                    'type' => 'public-key',
                    'transports' => ['internal'],
                ],
                [
                    'id' => 'credential-2',
                    'type' => 'public-key',
                    'transports' => ['usb'],
                ],
            ],
            $options['allowCredentials'],
        );
    }

    public function testRejectsUserWithoutActivePasskeys(): void
    {
        $pdo = $this->createMigratedConnection();
        $user = (new UserRepository($pdo))->create('user@example.com', 'password-hash');
        $service = new PasskeyAuthenticationChallengeService(
            WebAuthnConfig::fromEnvironment([]),
            new WebAuthnChallengeRepository($pdo),
            new UserPasskeyCredentialRepository($pdo),
        );

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Passkey authentication requires at least one active credential.');

        $service->start($user);
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
