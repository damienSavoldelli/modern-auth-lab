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

    public function testRedirectsAnonymousChallengeSubmissionToLogin(): void
    {
        $storage = [];
        $controller = new TotpChallengeController(
            new AuthSession($storage),
            new CsrfTokenManager($storage),
        );

        $response = $controller->submit([
            'csrf_token' => 'ignored',
            'code' => '123456',
        ]);

        self::assertSame(303, $response->statusCode);
        self::assertSame(['Location' => '/login'], $response->headers);
    }

    public function testRejectsInvalidCsrfOnChallengeSubmission(): void
    {
        $storage = [];
        $session = new AuthSession($storage);
        $session->markMfaPending(123, 'user@example.com');
        $controller = new TotpChallengeController(
            $session,
            new CsrfTokenManager($storage),
        );

        $response = $controller->submit([
            'csrf_token' => 'invalid',
            'code' => '123456',
        ]);

        self::assertSame(400, $response->statusCode);
        self::assertStringContainsString('Invalid authenticator code.', $response->body);
        self::assertArrayHasKey('totp_challenge_form', $storage['_csrf_tokens']);
    }

    public function testAcceptsCsrfButDoesNotVerifyTotpYet(): void
    {
        $storage = [];
        $session = new AuthSession($storage);
        $session->markMfaPending(123, 'user@example.com');
        $csrf = new CsrfTokenManager($storage);
        $controller = new TotpChallengeController($session, $csrf);
        $token = $csrf->issue('totp_challenge_form');

        $response = $controller->submit([
            'csrf_token' => $token->value,
            'code' => '123456',
        ]);

        self::assertSame(501, $response->statusCode);
        self::assertStringContainsString('TOTP verification is implemented in the next step.', $response->body);
    }
}
