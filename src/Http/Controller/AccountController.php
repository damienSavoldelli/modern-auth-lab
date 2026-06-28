<?php

declare(strict_types=1);

namespace ModernAuthLab\Http\Controller;

use ModernAuthLab\Http\Response;
use ModernAuthLab\Security\Csrf\CsrfTokenManager;
use ModernAuthLab\Session\AuthSession;

/**
 * Displays the first authenticated-only account page.
 *
 * This controller is intentionally small: it demonstrates server-side route
 * protection and issues the CSRF token used by logout.
 */
final readonly class AccountController
{
    private const CSRF_TOKEN_ID = 'logout_form';

    /**
     * Receive the current auth session and CSRF manager for account rendering.
     */
    public function __construct(
        private AuthSession $session,
        private CsrfTokenManager $csrf,
    ) {}

    /**
     * Show the account page or redirect anonymous/partial sessions to login.
     */
    public function show(): Response
    {
        if (! $this->session->state()->isFullyAuthenticated()) {
            return Response::redirect('/login');
        }

        $token = $this->csrf->issue(self::CSRF_TOKEN_ID);
        $escapedToken = htmlspecialchars($token->value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');

        return Response::html(<<<HTML
            <!doctype html>
            <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Account - Modern Auth Lab</title>
                </head>
                <body>
                    <main>
                        <h1>Account</h1>
                        <p>You are authenticated.</p>
                        <form method="post" action="/logout">
                            <input type="hidden" name="csrf_token" value="{$escapedToken}">
                            <button type="submit">Logout</button>
                        </form>
                    </main>
                </body>
            </html>
            HTML);
    }
}
