<?php

declare(strict_types=1);

namespace ModernAuthLab\Tests\Http\Controller;

use ModernAuthLab\Application\Security\SecurityEventLogger;
use ModernAuthLab\Application\WebAuthn\PasskeyEnrollmentChallengeService;
use ModernAuthLab\Application\WebAuthn\PasskeyEnrollmentVerificationService;
use ModernAuthLab\Domain\Security\SecurityEventType;
use ModernAuthLab\Domain\User\User;
use ModernAuthLab\Http\Controller\PasskeyEnrollmentController;
use ModernAuthLab\Infrastructure\Persistence\MigrationRepository;
use ModernAuthLab\Infrastructure\Persistence\MigrationRunner;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateSecurityEventsTable;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateUserPasskeyCredentialsTable;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateUsersTable;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateWebAuthnChallengesTable;
use ModernAuthLab\Infrastructure\Persistence\SecurityEventRepository;
use ModernAuthLab\Infrastructure\Persistence\UserPasskeyCredentialRepository;
use ModernAuthLab\Infrastructure\Persistence\UserRepository;
use ModernAuthLab\Infrastructure\Persistence\WebAuthnChallengeRepository;
use ModernAuthLab\Security\WebAuthn\Base64Url;
use ModernAuthLab\Security\WebAuthn\PasskeyAttestationVerifier;
use ModernAuthLab\Security\WebAuthn\VerifiedPasskeyCredential;
use ModernAuthLab\Security\WebAuthn\WebAuthnConfig;
use ModernAuthLab\Session\AuthSession;
use PDO;
use PHPUnit\Framework\TestCase;

final class PasskeyEnrollmentControllerTest extends TestCase
{
    public function testChallengeRejectsUnauthenticatedSession(): void
    {
        $context = $this->createContext();
        $controller = $this->createController($context, null);

        $response = $controller->challenge();

        self::assertSame(401, $response->statusCode);
        self::assertStringContainsString('unauthorized', $response->body);
    }

    public function testChallengeReturnsPublicKeyOptions(): void
    {
        $context = $this->createContext();
        $user = $context['users']->create('user@example.com', 'password-hash');
        $controller = $this->createController($context, $user);

        $response = $controller->challenge();

        self::assertSame(200, $response->statusCode);
        $payload = $this->decodeJson($response->body);
        self::assertArrayHasKey('publicKey', $payload);
        self::assertSame('127.0.0.1', $payload['publicKey']['rp']['id']);
        self::assertSame('user@example.com', $payload['publicKey']['user']['name']);
        self::assertNotEmpty($payload['publicKey']['challenge']);
    }

    public function testVerifyStoresCredentialAndLogsSuccess(): void
    {
        $context = $this->createContext();
        $user = $context['users']->create('user@example.com', 'password-hash');
        $result = $context['challengeService']->start($user);
        $storedChallenge = $result->challenge->challenge;
        $controller = $this->createController($context, $user);

        $response = $controller->verify([
            'credential' => $this->credentialPayload($storedChallenge),
            'name' => 'Work laptop',
        ]);

        self::assertSame(200, $response->statusCode);
        self::assertStringContainsString('"status":"ok"', $response->body);
        $active = $context['credentials']->findActiveByUserId($user->id);
        self::assertCount(1, $active);
        self::assertSame('Work laptop', $active[0]->name);
        self::assertSame(
            SecurityEventType::PasskeyEnrollmentSucceeded->value,
            $this->lastEventType($context['pdo']),
        );
    }

    public function testVerifyRejectsInvalidPayload(): void
    {
        $context = $this->createContext();
        $user = $context['users']->create('user@example.com', 'password-hash');
        $controller = $this->createController($context, $user);

        $response = $controller->verify(['credential' => 'not-an-array']);

        self::assertSame(400, $response->statusCode);
        self::assertStringContainsString('invalid_payload', $response->body);
        self::assertSame(
            SecurityEventType::PasskeyEnrollmentFailed->value,
            $this->lastEventType($context['pdo']),
        );
    }

    public function testVerifyLogsFailureWhenChallengeIsUnknown(): void
    {
        $context = $this->createContext();
        $user = $context['users']->create('user@example.com', 'password-hash');
        $controller = $this->createController($context, $user);

        $response = $controller->verify([
            'credential' => $this->credentialPayload('unknown-challenge'),
            'name' => 'Work laptop',
        ]);

        self::assertSame(400, $response->statusCode);
        self::assertStringContainsString('verification_failed', $response->body);
        self::assertSame(
            SecurityEventType::PasskeyEnrollmentFailed->value,
            $this->lastEventType($context['pdo']),
        );
    }

    /**
     * @return array{
     *   pdo: PDO,
     *   users: UserRepository,
     *   credentials: UserPasskeyCredentialRepository,
     *   challengeService: PasskeyEnrollmentChallengeService,
     *   verificationService: PasskeyEnrollmentVerificationService,
     *   session: AuthSession,
     *   storage: array<string, mixed>
     * }
     */
    private function createContext(): array
    {
        $pdo = new PDO('sqlite::memory:');
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
        $pdo->exec('PRAGMA foreign_keys = ON');
        (new MigrationRunner($pdo, new MigrationRepository($pdo), [
            new CreateUsersTable(),
            new CreateSecurityEventsTable(),
            new CreateUserPasskeyCredentialsTable(),
            new CreateWebAuthnChallengesTable(),
        ]))->run();

        $storage = [];

        return [
            'pdo' => $pdo,
            'users' => new UserRepository($pdo),
            'credentials' => new UserPasskeyCredentialRepository($pdo),
            'challengeService' => new PasskeyEnrollmentChallengeService(
                new WebAuthnConfig(
                    '127.0.0.1',
                    'Modern Auth Lab',
                    ['http://127.0.0.1:8080'],
                    300,
                    60000,
                    'preferred',
                ),
                new WebAuthnChallengeRepository($pdo),
                new UserPasskeyCredentialRepository($pdo),
            ),
            'verificationService' => new PasskeyEnrollmentVerificationService(
                new WebAuthnChallengeRepository($pdo),
                new UserPasskeyCredentialRepository($pdo),
                new PasskeyEnrollmentControllerFakeVerifier(),
            ),
            'session' => new AuthSession($storage),
            'storage' => &$storage,
        ];
    }

    /**
     * @param array<string, mixed> $context
     */
    private function createController(array $context, ?User $user): PasskeyEnrollmentController
    {
        if ($user !== null) {
            $context['session']->markFullyAuthenticated($user->id, $user->email);
        }

        return new PasskeyEnrollmentController(
            $context['session'],
            $context['users'],
            $context['challengeService'],
            $context['verificationService'],
            new SecurityEventLogger(new SecurityEventRepository($context['pdo'])),
            '203.0.113.1',
        );
    }

    /**
     * @return array<string, mixed>
     */
    private function credentialPayload(string $challenge): array
    {
        return [
            'id' => 'credential-id',
            'rawId' => 'credential-id',
            'type' => 'public-key',
            'response' => [
                'clientDataJSON' => Base64Url::encode((string) json_encode([
                    'type' => 'webauthn.create',
                    'challenge' => $challenge,
                    'origin' => 'http://127.0.0.1:8080',
                ], JSON_THROW_ON_ERROR)),
                'attestationObject' => 'stub-attestation',
            ],
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private function decodeJson(string $body): array
    {
        /** @var array<string, mixed> $decoded */
        $decoded = json_decode($body, true, flags: JSON_THROW_ON_ERROR);

        return $decoded;
    }

    private function lastEventType(PDO $pdo): ?string
    {
        $statement = $pdo->query('SELECT type FROM security_events ORDER BY id DESC LIMIT 1');

        if ($statement === false) {
            return null;
        }

        $row = $statement->fetch();

        return is_array($row) && is_string($row['type']) ? $row['type'] : null;
    }
}

final readonly class PasskeyEnrollmentControllerFakeVerifier implements PasskeyAttestationVerifier
{
    /**
     * @param array<string, mixed> $credential Browser credential response payload.
     */
    public function verify(User $user, string $challenge, array $credential): VerifiedPasskeyCredential
    {
        return new VerifiedPasskeyCredential(
            'verified-credential-id',
            'verified-public-key',
            0,
            ['internal'],
            'none',
            '00000000-0000-0000-0000-000000000000',
        );
    }
}
