<?php

declare(strict_types=1);

namespace ModernAuthLab\Tests\Http\Controller;

use ModernAuthLab\Http\Controller\AccountController;
use ModernAuthLab\Security\Csrf\CsrfTokenManager;
use ModernAuthLab\Session\AuthSession;
use PHPUnit\Framework\TestCase;

final class AccountControllerTest extends TestCase
{
    public function testRedirectsAnonymousUsersToLogin(): void
    {
        $storage = [];
        $controller = new AccountController(
            new AuthSession($storage),
            new CsrfTokenManager($storage),
        );

        $response = $controller->show();

        self::assertSame(303, $response->statusCode);
        self::assertSame(['Location' => '/login'], $response->headers);
    }

    public function testShowsAccountPageWithLogoutCsrfTokenForAuthenticatedUsers(): void
    {
        $storage = [];
        $session = new AuthSession($storage);
        $session->markFullyAuthenticated();
        $controller = new AccountController(
            $session,
            new CsrfTokenManager($storage),
        );

        $response = $controller->show();

        self::assertSame(200, $response->statusCode);
        self::assertStringContainsString('<h1>Account</h1>', $response->body);
        self::assertStringContainsString('<form method="post" action="/logout">', $response->body);
        self::assertStringContainsString('name="csrf_token"', $response->body);
        self::assertArrayHasKey('logout_form', $storage['_csrf_tokens']);
    }
}
