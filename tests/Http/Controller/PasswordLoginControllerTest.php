<?php

declare(strict_types=1);

namespace ModernAuthLab\Tests\Http\Controller;

use ModernAuthLab\Application\Auth\PasswordAuthenticator;
use ModernAuthLab\Application\Security\SecurityEventLogger;
use ModernAuthLab\Domain\Security\SecurityEventType;
use ModernAuthLab\Http\Controller\PasswordLoginController;
use ModernAuthLab\Infrastructure\Persistence\MigrationRepository;
use ModernAuthLab\Infrastructure\Persistence\MigrationRunner;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateSecurityEventsTable;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateUserPasskeyCredentialsTable;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateUsersTable;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateUserTotpCredentialsTable;
use ModernAuthLab\Infrastructure\Persistence\SecurityEventRepository;
use ModernAuthLab\Infrastructure\Persistence\UserPasskeyCredentialRepository;
use ModernAuthLab\Infrastructure\Persistence\UserRepository;
use ModernAuthLab\Infrastructure\Persistence\UserTotpCredentialRepository;
use ModernAuthLab\Security\Csrf\CsrfTokenManager;
use ModernAuthLab\Security\Password\PasswordHasher;
use ModernAuthLab\Security\RateLimit\LoginRateLimiter;
use ModernAuthLab\Session\AuthSession;
use ModernAuthLab\Session\AuthSessionState;
use ModernAuthLab\Session\PendingMfaMethod;
use PDO;
use PHPUnit\Framework\TestCase;

final class PasswordLoginControllerTest extends TestCase
{
    private SecurityEventRepository $events;

    public function testShowsLoginFormWithCsrfToken(): void
    {
        $storage = [];
        $controller = $this->createController($storage);

        $response = $controller->show();

        self::assertSame(200, $response->statusCode);
        self::assertStringContainsString('<form method="post" action="/login">', $response->body);
        self::assertStringContainsString('name="csrf_token"', $response->body);
        self::assertArrayHasKey('_csrf_tokens', $storage);
    }

    public function testMarksFullyAuthenticatedAndRotatesSessionOnSuccess(): void
    {
        $storage = [];
        $rotated = false;
        $controller = $this->createController($storage, static function () use (&$rotated): void {
            $rotated = true;
        });
        $token = (new CsrfTokenManager($storage))->issue('login_form');

        $response = $controller->submit([
            'csrf_token' => $token->value,
            'email' => 'user@example.com',
            'password' => 'correct password',
        ]);

        self::assertSame(303, $response->statusCode);
        self::assertSame(['Location' => '/account'], $response->headers);
        $session = new AuthSession($storage);
        self::assertSame(AuthSessionState::FullyAuthenticated, $session->state());
        self::assertNotNull($session->userId());
        self::assertSame('user@example.com', $session->userEmail());
        self::assertTrue($rotated);
        self::assertSame(SecurityEventType::PasswordLoginSucceeded->value, $this->events->all()[0]['type']);
    }

    public function testMarksMfaPendingAndRotatesSessionWhenUserHasActiveTotp(): void
    {
        $storage = [];
        $rotated = false;
        $controller = $this->createController($storage, static function () use (&$rotated): void {
            $rotated = true;
        }, hasActiveTotp: true);
        $token = (new CsrfTokenManager($storage))->issue('login_form');

        $response = $controller->submit([
            'csrf_token' => $token->value,
            'email' => 'user@example.com',
            'password' => 'correct password',
        ]);

        self::assertSame(303, $response->statusCode);
        self::assertSame(['Location' => '/login/totp'], $response->headers);
        $session = new AuthSession($storage);
        self::assertSame(AuthSessionState::MfaPending, $session->state());
        self::assertSame(1, $session->userId());
        self::assertSame('user@example.com', $session->userEmail());
        self::assertTrue($rotated);
        self::assertSame(SecurityEventType::PasswordLoginSucceeded->value, $this->events->all()[0]['type']);
    }

    public function testMarksMfaPendingAndRedirectsToPasskeyWhenUserHasActivePasskey(): void
    {
        $storage = [];
        $rotated = false;
        $controller = $this->createController($storage, static function () use (&$rotated): void {
            $rotated = true;
        }, hasActivePasskey: true);
        $token = (new CsrfTokenManager($storage))->issue('login_form');

        $response = $controller->submit([
            'csrf_token' => $token->value,
            'email' => 'user@example.com',
            'password' => 'correct password',
        ]);

        self::assertSame(303, $response->statusCode);
        self::assertSame(['Location' => '/login/passkey'], $response->headers);
        $session = new AuthSession($storage);
        self::assertSame(AuthSessionState::MfaPending, $session->state());
        self::assertSame(PendingMfaMethod::Passkey, $session->pendingMfaMethod());
        self::assertTrue($rotated);
    }

    public function testPrefersPasskeyOverTotpWhenBothAreActive(): void
    {
        $storage = [];
        $controller = $this->createController(
            $storage,
            null,
            hasActiveTotp: true,
            hasActivePasskey: true,
        );
        $token = (new CsrfTokenManager($storage))->issue('login_form');

        $response = $controller->submit([
            'csrf_token' => $token->value,
            'email' => 'user@example.com',
            'password' => 'correct password',
        ]);

        self::assertSame(['Location' => '/login/passkey'], $response->headers);
        self::assertSame(PendingMfaMethod::Passkey, (new AuthSession($storage))->pendingMfaMethod());
    }

    public function testRejectsInvalidPasswordWithoutChangingSessionState(): void
    {
        $storage = [];
        $rotated = false;
        $controller = $this->createController($storage, static function () use (&$rotated): void {
            $rotated = true;
        });
        $token = (new CsrfTokenManager($storage))->issue('login_form');

        $response = $controller->submit([
            'csrf_token' => $token->value,
            'email' => 'user@example.com',
            'password' => 'wrong password',
        ]);

        self::assertSame(401, $response->statusCode);
        self::assertSame(AuthSessionState::Anonymous, (new AuthSession($storage))->state());
        self::assertFalse($rotated);
        self::assertStringContainsString('Invalid credentials.', $response->body);
        self::assertSame(SecurityEventType::PasswordLoginFailed->value, $this->events->all()[0]['type']);
    }

    public function testRejectsInvalidCsrfTokenWithoutAuthenticating(): void
    {
        $storage = [];
        $controller = $this->createController($storage);

        $response = $controller->submit([
            'csrf_token' => 'invalid',
            'email' => 'user@example.com',
            'password' => 'correct password',
        ]);

        self::assertSame(401, $response->statusCode);
        self::assertSame(AuthSessionState::Anonymous, (new AuthSession($storage))->state());
    }

    public function testRateLimitsRepeatedInvalidPasswordAttempts(): void
    {
        $storage = [];
        $rotated = false;
        $controller = $this->createController($storage, static function () use (&$rotated): void {
            $rotated = true;
        });

        for ($attempt = 0; $attempt < 5; $attempt++) {
            $token = (new CsrfTokenManager($storage))->issue('login_form');

            $controller->submit([
                'csrf_token' => $token->value,
                'email' => 'user@example.com',
                'password' => 'wrong password',
            ]);
        }

        $token = (new CsrfTokenManager($storage))->issue('login_form');
        $response = $controller->submit([
            'csrf_token' => $token->value,
            'email' => 'user@example.com',
            'password' => 'correct password',
        ]);

        self::assertSame(429, $response->statusCode);
        self::assertSame(AuthSessionState::Anonymous, (new AuthSession($storage))->state());
        self::assertFalse($rotated);
        self::assertStringContainsString('Invalid credentials.', $response->body);
    }

    /**
     * @param array<string, mixed> $storage
     */
    private function createController(
        array &$storage,
        ?\Closure $rotateSessionId = null,
        bool $hasActiveTotp = false,
        bool $hasActivePasskey = false,
    ): PasswordLoginController {
        $passwords = new PasswordHasher();
        $pdo = $this->createMigratedConnection();
        $users = new UserRepository($pdo);
        $user = $users->create('user@example.com', $passwords->hash('correct password'));
        $totpCredentials = new UserTotpCredentialRepository($pdo);
        $passkeyCredentials = new UserPasskeyCredentialRepository($pdo);
        $this->events = new SecurityEventRepository($pdo);

        if ($hasActiveTotp) {
            $pending = $totpCredentials->createPending(
                $user->id,
                'test-ciphertext',
                'test-nonce',
                'local',
                'SHA1',
                6,
                30,
            );
            $totpCredentials->confirm($pending->id);
        }

        if ($hasActivePasskey) {
            $passkeyCredentials->createActive(
                $user->id,
                'stored-credential-id',
                'stored-public-key',
                0,
                'Work laptop',
            );
        }

        return new PasswordLoginController(
            new CsrfTokenManager($storage),
            new PasswordAuthenticator($users, $passwords),
            new AuthSession($storage),
            $totpCredentials,
            $passkeyCredentials,
            new LoginRateLimiter($storage),
            new SecurityEventLogger($this->events),
            '127.0.0.1',
            $rotateSessionId ?? static function (): void {},
        );
    }

    private function createMigratedConnection(): PDO
    {
        $pdo = new PDO('sqlite::memory:');
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);

        $runner = new MigrationRunner($pdo, new MigrationRepository($pdo), [
            new CreateUsersTable(),
            new CreateSecurityEventsTable(),
            new CreateUserTotpCredentialsTable(),
            new CreateUserPasskeyCredentialsTable(),
        ]);
        $runner->run();

        return $pdo;
    }
}
