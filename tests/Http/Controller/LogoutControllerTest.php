<?php

declare(strict_types=1);

namespace ModernAuthLab\Tests\Http\Controller;

use ModernAuthLab\Http\Controller\LogoutController;
use ModernAuthLab\Security\Csrf\CsrfTokenManager;
use ModernAuthLab\Session\AuthSession;
use ModernAuthLab\Session\AuthSessionState;
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
        $controller = new LogoutController(
            $session,
            new CsrfTokenManager($storage),
            static function () use (&$destroyed): void {
                $destroyed = true;
            },
        );

        $response = $controller->submit(['csrf_token' => $token->value]);

        self::assertSame(303, $response->statusCode);
        self::assertSame(['Location' => '/login'], $response->headers);
        self::assertSame(AuthSessionState::Anonymous, $session->state());
        self::assertTrue($destroyed);
    }

    public function testRejectsInvalidCsrfTokenWithoutDestroyingSession(): void
    {
        $storage = [];
        $session = new AuthSession($storage);
        $session->markFullyAuthenticated();
        (new CsrfTokenManager($storage))->issue('logout_form');
        $destroyed = false;
        $controller = new LogoutController(
            $session,
            new CsrfTokenManager($storage),
            static function () use (&$destroyed): void {
                $destroyed = true;
            },
        );

        $response = $controller->submit(['csrf_token' => 'invalid']);

        self::assertSame(400, $response->statusCode);
        self::assertSame(AuthSessionState::FullyAuthenticated, $session->state());
        self::assertFalse($destroyed);
    }
}
