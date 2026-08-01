<?php

declare(strict_types=1);

namespace ModernAuthLab\Http\Controller;

use ModernAuthLab\Application\Totp\TotpEnrollmentService;
use ModernAuthLab\Http\Response;
use ModernAuthLab\Security\Csrf\CsrfTokenException;
use ModernAuthLab\Security\Csrf\CsrfTokenManager;
use ModernAuthLab\Session\AuthSession;
use RuntimeException;

/**
 * Displays the first authenticated TOTP setup page.
 *
 * This controller starts or resumes a pending enrollment and renders the
 * provisioning data the user will later scan through a QR code.
 */
final readonly class TotpSetupController
{
    private const CSRF_TOKEN_ID = 'totp_setup_form';

    /**
     * @param AuthSession $session Current authentication session facade.
     * @param CsrfTokenManager $csrf CSRF token manager for setup confirmation.
     * @param TotpEnrollmentService $enrollment TOTP enrollment application service.
     */
    public function __construct(
        private AuthSession $session,
        private CsrfTokenManager $csrf,
        private TotpEnrollmentService $enrollment,
    ) {}

    /**
     * Show the TOTP setup page for a fully authenticated user.
     *
     * @return Response TOTP setup page, redirect, or setup-state message.
     */
    public function show(): Response
    {
        if (! $this->session->state()->isFullyAuthenticated()) {
            return Response::redirect('/login');
        }

        $userId = $this->session->userId();
        $email = $this->session->userEmail();

        if ($userId === null || $email === null) {
            return Response::redirect('/login');
        }

        try {
            $result = $this->enrollment->start($userId, $email);
        } catch (RuntimeException) {
            return Response::html($this->renderAlreadyActivePage());
        }

        return Response::html($this->renderSetupPage(
            $result->provisioningUri,
            $result->secretBase32,
            $result->created,
            $this->csrf->issue(self::CSRF_TOKEN_ID)->value,
        ));
    }

    /**
     * Confirm the pending TOTP enrollment with the submitted first code.
     *
     * @param array<string, mixed> $post Submitted form data.
     *
     * @return Response Redirect on success or setup page with generic error.
     */
    public function confirm(array $post): Response
    {
        if (! $this->session->state()->isFullyAuthenticated()) {
            return Response::redirect('/login');
        }

        $userId = $this->session->userId();
        if ($userId === null) {
            return Response::redirect('/login');
        }

        try {
            $this->csrf->consume(self::CSRF_TOKEN_ID, $this->stringValue($post['csrf_token'] ?? null));
        } catch (CsrfTokenException) {
            return $this->failedConfirmationResponse();
        }

        if (! $this->enrollment->confirm($userId, $this->stringValue($post['code'] ?? null))) {
            return $this->failedConfirmationResponse();
        }

        return Response::redirect('/account');
    }

    private function renderSetupPage(
        string $provisioningUri,
        string $secretBase32,
        bool $created,
        string $csrfToken,
        ?string $error = null,
    ): string {
        $escapedUri = htmlspecialchars($provisioningUri, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        $escapedSecret = htmlspecialchars($secretBase32, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        $escapedToken = htmlspecialchars($csrfToken, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        $status = $created ? 'New pending TOTP enrollment created.' : 'Pending TOTP enrollment resumed.';
        $errorHtml = $error === null
            ? ''
            : '<p role="alert">' . htmlspecialchars($error, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '</p>';

        return <<<HTML
            <!doctype html>
            <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>TOTP Setup - Modern Auth Lab</title>
                </head>
                <body>
                    <main>
                        <h1>TOTP Setup</h1>
                        <p>{$status}</p>
                        {$errorHtml}
                        <section aria-labelledby="provisioning-uri-title">
                            <h2 id="provisioning-uri-title">Provisioning URI</h2>
                            <textarea readonly rows="6" cols="80">{$escapedUri}</textarea>
                        </section>
                        <section aria-labelledby="manual-secret-title">
                            <h2 id="manual-secret-title">Manual Secret</h2>
                            <code>{$escapedSecret}</code>
                        </section>
                        <form method="post" action="/account/totp/setup">
                            <input type="hidden" name="csrf_token" value="{$escapedToken}">
                            <label>
                                Authenticator code
                                <input type="text" name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" required>
                            </label>
                            <button type="submit">Confirm TOTP</button>
                        </form>
                        <p>QR code rendering is intentionally handled in the next step.</p>
                        <p><a href="/account">Back to account</a></p>
                    </main>
                </body>
            </html>
            HTML;
    }

    private function failedConfirmationResponse(): Response
    {
        $userId = $this->session->userId();
        $email = $this->session->userEmail();

        if ($userId === null || $email === null) {
            return Response::redirect('/login');
        }

        try {
            $result = $this->enrollment->start($userId, $email);
        } catch (RuntimeException) {
            return Response::html($this->renderAlreadyActivePage());
        }

        return Response::html($this->renderSetupPage(
            $result->provisioningUri,
            $result->secretBase32,
            false,
            $this->csrf->issue(self::CSRF_TOKEN_ID)->value,
            'Invalid authenticator code.',
        ), 400);
    }

    private function renderAlreadyActivePage(): string
    {
        return <<<'HTML'
            <!doctype html>
            <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>TOTP Setup - Modern Auth Lab</title>
                </head>
                <body>
                    <main>
                        <h1>TOTP Setup</h1>
                        <p>TOTP is already active for this account.</p>
                        <p><a href="/account">Back to account</a></p>
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
