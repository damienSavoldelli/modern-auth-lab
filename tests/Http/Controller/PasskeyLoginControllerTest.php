<?php

declare(strict_types=1);

namespace ModernAuthLab\Tests\Http\Controller;

use ModernAuthLab\Application\Security\SecurityEventLogger;
use ModernAuthLab\Application\WebAuthn\PasskeyAuthenticationChallengeService;
use ModernAuthLab\Application\WebAuthn\PasskeyAuthenticationVerificationService;
use ModernAuthLab\Domain\Security\SecurityEventType;
use ModernAuthLab\Domain\User\User;
use ModernAuthLab\Http\Controller\PasskeyLoginController;
use ModernAuthLab\Infrastructure\Persistence\MigrationRepository;
use ModernAuthLab\Infrastructure\Persistence\MigrationRunner;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateSecurityEventsTable;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateUserPasskeyCredentialsTable;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateUsersTable;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateWebAuthnChallengesTable;
use ModernAuthLab\Infrastructure\Persistence\SecurityEventRepository;
use ModernAuthLab\Infrastructure\Persistence\UserPasskeyCredential;
use ModernAuthLab\Infrastructure\Persistence\UserPasskeyCredentialRepository;
use ModernAuthLab\Infrastructure\Persistence\UserRepository;
use ModernAuthLab\Infrastructure\Persistence\WebAuthnChallengeRepository;
use ModernAuthLab\Security\WebAuthn\Base64Url;
use ModernAuthLab\Security\WebAuthn\PasskeyAssertionVerifier;
use ModernAuthLab\Security\WebAuthn\VerifiedPasskeyAssertion;
use ModernAuthLab\Security\WebAuthn\WebAuthnConfig;
use ModernAuthLab\Session\AuthSession;
use ModernAuthLab\Session\AuthSessionState;
use ModernAuthLab\Session\PendingMfaMethod;
use PDO;
use PHPUnit\Framework\TestCase;

final class PasskeyLoginControllerTest extends TestCase
{
    public function testShowRedirectsWhenSessionIsNotMfaPending(): void
    {
        $context = $this->createContext();
        $controller = $this->createController($context);

        $response = $controller->show();

        self::assertSame(303, $response->statusCode);
        self::assertSame(['Location' => '/login'], $response->headers);
    }

    public function testShowRedirectsWhenPendingMethodIsNotPasskey(): void
    {
        $context = $this->createContext();
        $user = $context['users']->create('user@example.com', 'hash');
        $context['session']->markMfaPending($user->id, $user->email, PendingMfaMethod::Totp);
        $controller = $this->createController($context);

        $response = $controller->show();

        self::assertSame(303, $response->statusCode);
        self::assertSame(['Location' => '/login'], $response->headers);
    }

    public function testShowReturnsChallengePageWhenSessionIsPasskeyPending(): void
    {
        $context = $this->createContext();
        $user = $this->prepareUserWithPasskey($context);
        $context['session']->markMfaPending($user->id, $user->email, PendingMfaMethod::Passkey);
        $controller = $this->createController($context);

        $response = $controller->show();

        self::assertSame(200, $response->statusCode);
        self::assertStringContainsString('<h1>Passkey Login</h1>', $response->body);
    }

    public function testChallengeReturnsAllowedCredentials(): void
    {
        $context = $this->createContext();
        $user = $this->prepareUserWithPasskey($context);
        $context['session']->markMfaPending($user->id, $user->email, PendingMfaMethod::Passkey);
        $controller = $this->createController($context);

        $response = $controller->challenge();

        self::assertSame(200, $response->statusCode);
        $payload = $this->decodeJson($response->body);
        self::assertNotEmpty($payload['publicKey']['allowCredentials']);
        self::assertSame('stored-credential-id', $payload['publicKey']['allowCredentials'][0]['id']);
    }

    public function testChallengeReturns401WhenSessionIsNotEligible(): void
    {
        $context = $this->createContext();
        $controller = $this->createController($context);

        $response = $controller->challenge();

        self::assertSame(401, $response->statusCode);
    }

    public function testVerifyPromotesSessionAndLogsSuccess(): void
    {
        $context = $this->createContext();
        $user = $this->prepareUserWithPasskey($context);
        $context['session']->markMfaPending($user->id, $user->email, PendingMfaMethod::Passkey);
        $challenge = $context['challengeService']->start($user)->challenge->challenge;
        $rotated = false;
        $controller = $this->createController($context, static function () use (&$rotated): void {
            $rotated = true;
        });

        $response = $controller->verify([
            'credential' => $this->assertionPayload($challenge),
        ]);

        self::assertSame(200, $response->statusCode);
        self::assertStringContainsString('"redirect":"/account"', $response->body);
        self::assertSame(AuthSessionState::FullyAuthenticated, $context['session']->state());
        self::assertTrue($rotated);
        self::assertSame(
            SecurityEventType::PasskeyAuthenticationSucceeded->value,
            $this->lastEventType($context['pdo']),
        );
    }

    public function testVerifyRejectsInvalidPayload(): void
    {
        $context = $this->createContext();
        $user = $this->prepareUserWithPasskey($context);
        $context['session']->markMfaPending($user->id, $user->email, PendingMfaMethod::Passkey);
        $controller = $this->createController($context);

        $response = $controller->verify(['credential' => 'not-an-array']);

        self::assertSame(400, $response->statusCode);
        self::assertSame(
            SecurityEventType::PasskeyAuthenticationFailed->value,
            $this->lastEventType($context['pdo']),
        );
    }

    public function testVerifyLogsFailureWhenAssertionVerificationFails(): void
    {
        $context = $this->createContext();
        $user = $this->prepareUserWithPasskey($context);
        $context['session']->markMfaPending($user->id, $user->email, PendingMfaMethod::Passkey);
        $controller = $this->createController($context);

        $response = $controller->verify([
            'credential' => $this->assertionPayload('unknown-challenge'),
        ]);

        self::assertSame(400, $response->statusCode);
        self::assertStringContainsString('verification_failed', $response->body);
        self::assertSame(
            SecurityEventType::PasskeyAuthenticationFailed->value,
            $this->lastEventType($context['pdo']),
        );
    }

    /**
     * @return array{
     *   pdo: PDO,
     *   users: UserRepository,
     *   credentials: UserPasskeyCredentialRepository,
     *   challengeService: PasskeyAuthenticationChallengeService,
     *   verificationService: PasskeyAuthenticationVerificationService,
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
        $config = new WebAuthnConfig(
            '127.0.0.1',
            'Modern Auth Lab',
            ['http://127.0.0.1:8080'],
            300,
            60_000,
            'preferred',
        );

        return [
            'pdo' => $pdo,
            'users' => new UserRepository($pdo),
            'credentials' => new UserPasskeyCredentialRepository($pdo),
            'challengeService' => new PasskeyAuthenticationChallengeService(
                $config,
                new WebAuthnChallengeRepository($pdo),
                new UserPasskeyCredentialRepository($pdo),
            ),
            'verificationService' => new PasskeyAuthenticationVerificationService(
                new WebAuthnChallengeRepository($pdo),
                new UserPasskeyCredentialRepository($pdo),
                new PasskeyLoginControllerFakeAssertionVerifier(),
            ),
            'session' => new AuthSession($storage),
            'storage' => &$storage,
        ];
    }

    /**
     * @param array<string, mixed> $context
     */
    private function prepareUserWithPasskey(array $context): User
    {
        $user = $context['users']->create('user@example.com', 'hash');
        $context['credentials']->createActive(
            $user->id,
            'stored-credential-id',
            'stored-public-key',
            0,
            'Work laptop',
        );

        return $user;
    }

    /**
     * @param array<string, mixed> $context
     */
    private function createController(array $context, ?\Closure $rotate = null): PasskeyLoginController
    {
        return new PasskeyLoginController(
            $context['session'],
            $context['users'],
            $context['challengeService'],
            $context['verificationService'],
            new SecurityEventLogger(new SecurityEventRepository($context['pdo'])),
            '203.0.113.1',
            $rotate ?? static function (): void {},
        );
    }

    /**
     * @return array<string, mixed>
     */
    private function assertionPayload(string $challenge): array
    {
        return [
            'id' => 'stored-credential-id',
            'rawId' => 'stored-credential-id',
            'type' => 'public-key',
            'response' => [
                'clientDataJSON' => Base64Url::encode((string) json_encode([
                    'type' => 'webauthn.get',
                    'challenge' => $challenge,
                    'origin' => 'http://127.0.0.1:8080',
                ], JSON_THROW_ON_ERROR)),
                'authenticatorData' => 'stub-authenticator-data',
                'signature' => 'stub-signature',
                'userHandle' => null,
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

final readonly class PasskeyLoginControllerFakeAssertionVerifier implements PasskeyAssertionVerifier
{
    /**
     * @param array<string, mixed> $assertion
     */
    public function verify(
        UserPasskeyCredential $credential,
        string $challenge,
        array $assertion,
    ): VerifiedPasskeyAssertion {
        return new VerifiedPasskeyAssertion($credential->credentialId, $credential->signCount + 1);
    }
}
