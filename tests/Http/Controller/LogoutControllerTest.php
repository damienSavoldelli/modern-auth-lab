<?php

declare(strict_types=1);

namespace ModernAuthLab\Tests\Http\Controller;

use ModernAuthLab\Application\Security\SecurityEventLogger;
use ModernAuthLab\Domain\Security\SecurityEventType;
use ModernAuthLab\Http\Controller\LogoutController;
use ModernAuthLab\Infrastructure\Persistence\MigrationRepository;
use ModernAuthLab\Infrastructure\Persistence\MigrationRunner;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateSecurityEventsTable;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateUsersTable;
use ModernAuthLab\Infrastructure\Persistence\SecurityEventRepository;
use ModernAuthLab\Security\Csrf\CsrfTokenManager;
use ModernAuthLab\Session\AuthSession;
use ModernAuthLab\Session\AuthSessionState;
use PDO;
use PHPUnit\Framework\TestCase;

final class LogoutControllerTest extends TestCase
{
    public function testClearsAuthenticationDestroysSessionAndRedirectsToLogin(): void
    {
        $storage = [];
        $session = new AuthSession($storage);
        $session->markFullyAuthenticated();
        $token = (new CsrfTokenManager($storage))->issue('logout_form');
        $destroyed = false;
        $events = new SecurityEventRepository($this->createMigratedConnection());
        $controller = new LogoutController(
            $session,
            new CsrfTokenManager($storage),
            new SecurityEventLogger($events),
            '127.0.0.1',
            static function () use (&$destroyed): void {
                $destroyed = true;
            },
        );

        $response = $controller->submit(['csrf_token' => $token->value]);

        self::assertSame(303, $response->statusCode);
        self::assertSame(['Location' => '/login'], $response->headers);
        self::assertSame(AuthSessionState::Anonymous, $session->state());
        self::assertTrue($destroyed);
        self::assertSame(SecurityEventType::LogoutSucceeded->value, $events->all()[0]['type']);
    }

    public function testRejectsInvalidCsrfTokenWithoutDestroyingSession(): void
    {
        $storage = [];
        $session = new AuthSession($storage);
        $session->markFullyAuthenticated();
        (new CsrfTokenManager($storage))->issue('logout_form');
        $destroyed = false;
        $events = new SecurityEventRepository($this->createMigratedConnection());
        $controller = new LogoutController(
            $session,
            new CsrfTokenManager($storage),
            new SecurityEventLogger($events),
            '127.0.0.1',
            static function () use (&$destroyed): void {
                $destroyed = true;
            },
        );

        $response = $controller->submit(['csrf_token' => 'invalid']);

        self::assertSame(400, $response->statusCode);
        self::assertSame(AuthSessionState::FullyAuthenticated, $session->state());
        self::assertFalse($destroyed);
        self::assertSame(SecurityEventType::LogoutCsrfFailed->value, $events->all()[0]['type']);
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
