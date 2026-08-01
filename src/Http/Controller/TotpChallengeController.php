<?php

declare(strict_types=1);

namespace ModernAuthLab\Http\Controller;

use ModernAuthLab\Http\Response;
use ModernAuthLab\Security\Csrf\CsrfTokenManager;
use ModernAuthLab\Session\AuthSession;
use ModernAuthLab\Session\AuthSessionState;

/**
 * Handles the TOTP challenge shown after successful password verification.
 *
 * This controller is intentionally separate from TOTP setup. Setup provisions a
 * new shared secret, while the challenge proves possession of an already active
 * secret during login.
 */
final readonly class TotpChallengeController
{
    private const CSRF_TOKEN_ID = 'totp_challenge_form';

    /**
     * @param AuthSession $session Current authentication session facade.
     * @param CsrfTokenManager $csrf CSRF token manager for challenge submission.
     */
    public function __construct(
        private AuthSession $session,
        private CsrfTokenManager $csrf,
    ) {}

    /**
     * Render the TOTP challenge form for MFA-pending sessions.
     *
     * @return Response Challenge form or redirect when the session is not eligible.
     */
    public function show(): Response
    {
        if ($this->session->state() === AuthSessionState::FullyAuthenticated) {
            return Response::redirect('/account');
        }

        if ($this->session->state() !== AuthSessionState::MfaPending || $this->session->userId() === null) {
            return Response::redirect('/login');
        }

        return Response::html($this->renderForm($this->csrf->issue(self::CSRF_TOKEN_ID)->value));
    }

    private function renderForm(string $csrfToken): string
    {
        $escapedToken = htmlspecialchars($csrfToken, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');

        return <<<HTML
            <!doctype html>
            <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>TOTP Challenge - Modern Auth Lab</title>
                </head>
                <body>
                    <main>
                        <h1>TOTP Challenge</h1>
                        <form method="post" action="/login/totp">
                            <input type="hidden" name="csrf_token" value="{$escapedToken}">
                            <label>
                                Authenticator code
                                <input type="text" name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" required>
                            </label>
                            <button type="submit">Verify TOTP</button>
                        </form>
                    </main>
                </body>
            </html>
            HTML;
    }
}
