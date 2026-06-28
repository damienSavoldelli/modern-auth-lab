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
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateUsersTable;
use ModernAuthLab\Infrastructure\Persistence\SecurityEventRepository;
use ModernAuthLab\Infrastructure\Persistence\UserRepository;
use ModernAuthLab\Security\Csrf\CsrfTokenManager;
use ModernAuthLab\Security\Password\PasswordHasher;
use ModernAuthLab\Security\RateLimit\LoginRateLimiter;
use ModernAuthLab\Session\AuthSession;
use ModernAuthLab\Session\AuthSessionState;
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
        self::assertSame(AuthSessionState::FullyAuthenticated, (new AuthSession($storage))->state());
        self::assertTrue($rotated);
        self::assertSame(SecurityEventType::PasswordLoginSucceeded->value, $this->events->all()[0]['type']);
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
    private function createController(array &$storage, ?\Closure $rotateSessionId = null): PasswordLoginController
    {
        $passwords = new PasswordHasher();
        $pdo = $this->createMigratedConnection();
        $users = new UserRepository($pdo);
        $users->create('user@example.com', $passwords->hash('correct password'));
        $this->events = new SecurityEventRepository($pdo);

        return new PasswordLoginController(
            new CsrfTokenManager($storage),
            new PasswordAuthenticator($users, $passwords),
            new AuthSession($storage),
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
        ]);
        $runner->run();

        return $pdo;
    }
}
