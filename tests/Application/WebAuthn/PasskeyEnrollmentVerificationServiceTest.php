<?php

declare(strict_types=1);

namespace ModernAuthLab\Tests\Application\WebAuthn;

use DateTimeImmutable;
use ModernAuthLab\Application\WebAuthn\PasskeyEnrollmentVerificationService;
use ModernAuthLab\Domain\User\User;
use ModernAuthLab\Infrastructure\Persistence\MigrationRepository;
use ModernAuthLab\Infrastructure\Persistence\MigrationRunner;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateUserPasskeyCredentialsTable;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateUsersTable;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateWebAuthnChallengesTable;
use ModernAuthLab\Infrastructure\Persistence\UserPasskeyCredentialRepository;
use ModernAuthLab\Infrastructure\Persistence\UserRepository;
use ModernAuthLab\Infrastructure\Persistence\WebAuthnChallengeRepository;
use ModernAuthLab\Security\WebAuthn\PasskeyAttestationVerifier;
use ModernAuthLab\Security\WebAuthn\VerifiedPasskeyCredential;
use PDO;
use PHPUnit\Framework\TestCase;

final class PasskeyEnrollmentVerificationServiceTest extends TestCase
{
    public function testVerifiesEnrollmentAndStoresCredential(): void
    {
        $pdo = $this->createMigratedConnection();
        $user = (new UserRepository($pdo))->create('user@example.com', 'password-hash');
        $challenges = new WebAuthnChallengeRepository($pdo);
        $credentials = new UserPasskeyCredentialRepository($pdo);
        $challenges->create($user->id, 'enrollment', 'challenge', new DateTimeImmutable('+5 minutes'));
        $service = new PasskeyEnrollmentVerificationService(
            $challenges,
            $credentials,
            new FakePasskeyAttestationVerifier(),
        );

        $result = $service->verify($user, 'challenge', ['id' => 'browser-payload'], 'Work laptop');

        self::assertSame($user->id, $result->credential->userId);
        self::assertSame('verified-credential-id', $result->credential->credentialId);
        self::assertSame('verified-public-key', $result->credential->publicKey);
        self::assertSame(12, $result->credential->signCount);
        self::assertSame('Work laptop', $result->credential->name);
        self::assertSame(['internal'], $result->credential->transports);
        self::assertSame('none', $result->credential->attestationType);
        self::assertSame('00000000-0000-0000-0000-000000000000', $result->credential->aaguid);
        self::assertNull($challenges->findUnconsumed($user->id, 'enrollment', 'challenge'));
    }

    public function testUsesDefaultNameWhenSubmittedNameIsBlank(): void
    {
        $pdo = $this->createMigratedConnection();
        $user = (new UserRepository($pdo))->create('user@example.com', 'password-hash');
        $challenges = new WebAuthnChallengeRepository($pdo);
        $challenges->create($user->id, 'enrollment', 'challenge', new DateTimeImmutable('+5 minutes'));
        $service = new PasskeyEnrollmentVerificationService(
            $challenges,
            new UserPasskeyCredentialRepository($pdo),
            new FakePasskeyAttestationVerifier(),
        );

        $result = $service->verify($user, 'challenge', [], '   ');

        self::assertSame('Passkey', $result->credential->name);
    }

    public function testRejectsMissingChallenge(): void
    {
        $pdo = $this->createMigratedConnection();
        $user = (new UserRepository($pdo))->create('user@example.com', 'password-hash');
        $service = new PasskeyEnrollmentVerificationService(
            new WebAuthnChallengeRepository($pdo),
            new UserPasskeyCredentialRepository($pdo),
            new FakePasskeyAttestationVerifier(),
        );

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Passkey enrollment challenge was not found.');

        $service->verify($user, 'missing-challenge', [], 'Passkey');
    }

    public function testRejectsExpiredChallenge(): void
    {
        $pdo = $this->createMigratedConnection();
        $user = (new UserRepository($pdo))->create('user@example.com', 'password-hash');
        $challenges = new WebAuthnChallengeRepository($pdo);
        $challenges->create($user->id, 'enrollment', 'challenge', new DateTimeImmutable('-1 minute'));
        $service = new PasskeyEnrollmentVerificationService(
            $challenges,
            new UserPasskeyCredentialRepository($pdo),
            new FakePasskeyAttestationVerifier(),
        );

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Passkey enrollment challenge has expired.');

        $service->verify($user, 'challenge', [], 'Passkey');
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

final readonly class FakePasskeyAttestationVerifier implements PasskeyAttestationVerifier
{
    /**
     * @param array<string, mixed> $credential Browser credential response payload.
     */
    public function verify(User $user, string $challenge, array $credential): VerifiedPasskeyCredential
    {
        return new VerifiedPasskeyCredential(
            'verified-credential-id',
            'verified-public-key',
            12,
            ['internal'],
            'none',
            '00000000-0000-0000-0000-000000000000',
        );
    }
}
