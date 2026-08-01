<?php

declare(strict_types=1);

namespace ModernAuthLab\Tests\Http\Controller;

use ModernAuthLab\Http\Controller\TotpChallengeController;
use ModernAuthLab\Security\Csrf\CsrfTokenManager;
use ModernAuthLab\Session\AuthSession;
use PHPUnit\Framework\TestCase;

final class TotpChallengeControllerTest extends TestCase
{
    public function testRedirectsAnonymousUsersToLogin(): void
    {
        $storage = [];
        $controller = new TotpChallengeController(
            new AuthSession($storage),
            new CsrfTokenManager($storage),
        );

        $response = $controller->show();

        self::assertSame(303, $response->statusCode);
        self::assertSame(['Location' => '/login'], $response->headers);
    }

    public function testRedirectsFullyAuthenticatedUsersToAccount(): void
    {
        $storage = [];
        $session = new AuthSession($storage);
        $session->markFullyAuthenticated(123, 'user@example.com');
        $controller = new TotpChallengeController(
            $session,
            new CsrfTokenManager($storage),
        );

        $response = $controller->show();

        self::assertSame(303, $response->statusCode);
        self::assertSame(['Location' => '/account'], $response->headers);
    }

    public function testRedirectsMfaPendingSessionWithoutUserIdentityToLogin(): void
    {
        $storage = [];
        $session = new AuthSession($storage);
        $session->markMfaPending();
        $controller = new TotpChallengeController(
            $session,
            new CsrfTokenManager($storage),
        );

        $response = $controller->show();

        self::assertSame(303, $response->statusCode);
        self::assertSame(['Location' => '/login'], $response->headers);
    }

    public function testShowsChallengeFormForMfaPendingSessionWithUserIdentity(): void
    {
        $storage = [];
        $session = new AuthSession($storage);
        $session->markMfaPending(123, 'user@example.com');
        $controller = new TotpChallengeController(
            $session,
            new CsrfTokenManager($storage),
        );

        $response = $controller->show();

        self::assertSame(200, $response->statusCode);
        self::assertStringContainsString('<h1>TOTP Challenge</h1>', $response->body);
        self::assertStringContainsString('<form method="post" action="/login/totp">', $response->body);
        self::assertStringContainsString('name="csrf_token"', $response->body);
        self::assertStringContainsString('autocomplete="one-time-code"', $response->body);
        self::assertArrayHasKey('totp_challenge_form', $storage['_csrf_tokens']);
    }
}
