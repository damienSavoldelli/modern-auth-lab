<?php

declare(strict_types=1);

namespace ModernAuthLab\Tests\Http\Controller;

use ModernAuthLab\Application\Auth\PasswordAuthenticator;
use ModernAuthLab\Http\Controller\PasswordLoginController;
use ModernAuthLab\Infrastructure\Persistence\MigrationRepository;
use ModernAuthLab\Infrastructure\Persistence\MigrationRunner;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateUsersTable;
use ModernAuthLab\Infrastructure\Persistence\UserRepository;
use ModernAuthLab\Security\Csrf\CsrfTokenManager;
use ModernAuthLab\Security\Password\PasswordHasher;
use ModernAuthLab\Session\AuthSession;
use ModernAuthLab\Session\AuthSessionState;
use PDO;
use PHPUnit\Framework\TestCase;

final class PasswordLoginControllerTest extends TestCase
{
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

    /**
     * @param array<string, mixed> $storage
     */
    private function createController(array &$storage, ?\Closure $rotateSessionId = null): PasswordLoginController
    {
        $passwords = new PasswordHasher();
        $users = new UserRepository($this->createMigratedConnection());
        $users->create('user@example.com', $passwords->hash('correct password'));

        return new PasswordLoginController(
            new CsrfTokenManager($storage),
            new PasswordAuthenticator($users, $passwords),
            new AuthSession($storage),
            $rotateSessionId ?? static function (): void {},
        );
    }

    private function createMigratedConnection(): PDO
    {
        $pdo = new PDO('sqlite::memory:');
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);

        $runner = new MigrationRunner($pdo, new MigrationRepository($pdo), [new CreateUsersTable()]);
        $runner->run();

        return $pdo;
    }
}
