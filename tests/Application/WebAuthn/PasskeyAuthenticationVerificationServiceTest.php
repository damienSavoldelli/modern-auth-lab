<?php

declare(strict_types=1);

namespace ModernAuthLab\Tests\Application\WebAuthn;

use DateTimeImmutable;
use ModernAuthLab\Application\WebAuthn\PasskeyAuthenticationVerificationService;
use ModernAuthLab\Infrastructure\Persistence\MigrationRepository;
use ModernAuthLab\Infrastructure\Persistence\MigrationRunner;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateUserPasskeyCredentialsTable;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateUsersTable;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateWebAuthnChallengesTable;
use ModernAuthLab\Infrastructure\Persistence\UserPasskeyCredential;
use ModernAuthLab\Infrastructure\Persistence\UserPasskeyCredentialRepository;
use ModernAuthLab\Infrastructure\Persistence\UserRepository;
use ModernAuthLab\Infrastructure\Persistence\WebAuthnChallengeRepository;
use ModernAuthLab\Security\WebAuthn\PasskeyAssertionVerifier;
use ModernAuthLab\Security\WebAuthn\VerifiedPasskeyAssertion;
use PDO;
use PHPUnit\Framework\TestCase;

final class PasskeyAuthenticationVerificationServiceTest extends TestCase
{
    public function testVerifiesAssertionAndUpdatesCredentialState(): void
    {
        $pdo = $this->createMigratedConnection();
        $user = (new UserRepository($pdo))->create('user@example.com', 'password-hash');
        $credentials = new UserPasskeyCredentialRepository($pdo);
        $credentials->createActive($user->id, 'credential-id', 'public-key', 0, 'Work laptop');
        $challenges = new WebAuthnChallengeRepository($pdo);
        $challenges->create($user->id, 'authentication', 'challenge', new DateTimeImmutable('+5 minutes'));
        $service = new PasskeyAuthenticationVerificationService(
            $challenges,
            $credentials,
            new FakePasskeyAssertionVerifier(42),
        );

        $result = $service->verify($user->id, 'challenge', ['id' => 'credential-id']);

        self::assertSame($user->id, $result->userId);
        self::assertSame(42, $result->credential->signCount);
        self::assertNotNull($result->credential->lastUsedAt);
        self::assertNull($challenges->findUnconsumed($user->id, 'authentication', 'challenge'));
    }

    public function testRejectsMissingChallenge(): void
    {
        $pdo = $this->createMigratedConnection();
        $user = (new UserRepository($pdo))->create('user@example.com', 'password-hash');
        $service = new PasskeyAuthenticationVerificationService(
            new WebAuthnChallengeRepository($pdo),
            new UserPasskeyCredentialRepository($pdo),
            new FakePasskeyAssertionVerifier(0),
        );

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Passkey authentication challenge was not found.');

        $service->verify($user->id, 'missing-challenge', ['id' => 'credential-id']);
    }

    public function testRejectsExpiredChallenge(): void
    {
        $pdo = $this->createMigratedConnection();
        $user = (new UserRepository($pdo))->create('user@example.com', 'password-hash');
        $challenges = new WebAuthnChallengeRepository($pdo);
        $challenges->create($user->id, 'authentication', 'challenge', new DateTimeImmutable('-1 minute'));
        $service = new PasskeyAuthenticationVerificationService(
            $challenges,
            new UserPasskeyCredentialRepository($pdo),
            new FakePasskeyAssertionVerifier(0),
        );

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Passkey authentication challenge has expired.');

        $service->verify($user->id, 'challenge', ['id' => 'credential-id']);
    }

    public function testRejectsAssertionMissingCredentialId(): void
    {
        $pdo = $this->createMigratedConnection();
        $user = (new UserRepository($pdo))->create('user@example.com', 'password-hash');
        $challenges = new WebAuthnChallengeRepository($pdo);
        $challenges->create($user->id, 'authentication', 'challenge', new DateTimeImmutable('+5 minutes'));
        $service = new PasskeyAuthenticationVerificationService(
            $challenges,
            new UserPasskeyCredentialRepository($pdo),
            new FakePasskeyAssertionVerifier(0),
        );

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Passkey assertion is missing a credential id.');

        $service->verify($user->id, 'challenge', []);
    }

    public function testRejectsUnknownCredential(): void
    {
        $pdo = $this->createMigratedConnection();
        $user = (new UserRepository($pdo))->create('user@example.com', 'password-hash');
        $challenges = new WebAuthnChallengeRepository($pdo);
        $challenges->create($user->id, 'authentication', 'challenge', new DateTimeImmutable('+5 minutes'));
        $service = new PasskeyAuthenticationVerificationService(
            $challenges,
            new UserPasskeyCredentialRepository($pdo),
            new FakePasskeyAssertionVerifier(0),
        );

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Passkey credential was not found.');

        $service->verify($user->id, 'challenge', ['id' => 'not-stored']);
    }

    public function testRejectsCredentialBelongingToADifferentUser(): void
    {
        $pdo = $this->createMigratedConnection();
        $users = new UserRepository($pdo);
        $alice = $users->create('alice@example.com', 'hash');
        $bob = $users->create('bob@example.com', 'hash');
        $credentials = new UserPasskeyCredentialRepository($pdo);
        $credentials->createActive($alice->id, 'credential-id', 'public-key', 0, 'Alice laptop');
        $challenges = new WebAuthnChallengeRepository($pdo);
        $challenges->create($bob->id, 'authentication', 'challenge', new DateTimeImmutable('+5 minutes'));
        $service = new PasskeyAuthenticationVerificationService(
            $challenges,
            $credentials,
            new FakePasskeyAssertionVerifier(0),
        );

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Passkey credential does not belong to the current login attempt.');

        $service->verify($bob->id, 'challenge', ['id' => 'credential-id']);
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

final readonly class FakePasskeyAssertionVerifier implements PasskeyAssertionVerifier
{
    public function __construct(private int $signCount) {}

    /**
     * @param array<string, mixed> $assertion
     */
    public function verify(
        UserPasskeyCredential $credential,
        string $challenge,
        array $assertion,
    ): VerifiedPasskeyAssertion {
        return new VerifiedPasskeyAssertion($credential->credentialId, $this->signCount);
    }
}
