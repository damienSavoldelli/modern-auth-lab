<?php

declare(strict_types=1);

namespace ModernAuthLab\Http\Controller;

use Closure;
use ModernAuthLab\Application\Totp\TotpLoginVerificationService;
use ModernAuthLab\Http\Response;
use ModernAuthLab\Security\Csrf\CsrfTokenException;
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
     * @param TotpLoginVerificationService $verification TOTP login verification service.
     * @param Closure(): void $rotateSessionId Session id rotation callback.
     */
    public function __construct(
        private AuthSession $session,
        private CsrfTokenManager $csrf,
        private TotpLoginVerificationService $verification,
        private Closure $rotateSessionId,
    ) {}

    /**
     * Render the TOTP challenge form for MFA-pending sessions.
     *
     * @return Response Challenge form or redirect when the session is not eligible.
     */
    public function show(): Response
    {
        $redirect = $this->redirectWhenSessionCannotUseChallenge();
        if ($redirect !== null) {
            return $redirect;
        }

        return Response::html($this->renderForm($this->csrf->issue(self::CSRF_TOKEN_ID)->value));
    }

    /**
     * Process the TOTP challenge form submission.
     *
     * @param array<string, mixed> $post Submitted form data.
     *
     * @return Response Redirect on success, generic failure, or redirect.
     */
    public function submit(array $post): Response
    {
        $redirect = $this->redirectWhenSessionCannotUseChallenge();
        if ($redirect !== null) {
            return $redirect;
        }

        try {
            $this->csrf->consume(self::CSRF_TOKEN_ID, $this->stringValue($post['csrf_token'] ?? null));
        } catch (CsrfTokenException) {
            return $this->failedChallengeResponse();
        }

        $userId = $this->session->userId();
        $email = $this->session->userEmail();

        if ($userId === null || $email === null) {
            return Response::redirect('/login');
        }

        $result = $this->verification->verify($userId, $this->stringValue($post['code'] ?? null));
        if (! $result->success) {
            return $this->failedChallengeResponse();
        }

        $this->session->markFullyAuthenticated($userId, $email);
        ($this->rotateSessionId)();

        return Response::redirect('/account');
    }

    private function redirectWhenSessionCannotUseChallenge(): ?Response
    {
        if ($this->session->state() === AuthSessionState::FullyAuthenticated) {
            return Response::redirect('/account');
        }

        if ($this->session->state() !== AuthSessionState::MfaPending || $this->session->userId() === null) {
            return Response::redirect('/login');
        }

        return null;
    }

    private function failedChallengeResponse(): Response
    {
        return Response::html(
            $this->renderForm(
                $this->csrf->issue(self::CSRF_TOKEN_ID)->value,
                'Invalid authenticator code.',
            ),
            400,
        );
    }

    private function renderForm(string $csrfToken, ?string $error = null): string
    {
        $escapedToken = htmlspecialchars($csrfToken, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        $errorHtml = $error === null
            ? ''
            : '<p role="alert">' . htmlspecialchars($error, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '</p>';

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
                        {$errorHtml}
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

    private function stringValue(mixed $value): string
    {
        return is_string($value) ? $value : '';
    }
}
