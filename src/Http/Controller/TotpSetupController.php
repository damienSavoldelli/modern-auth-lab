<?php

declare(strict_types=1);

namespace ModernAuthLab\Http\Controller;

use ModernAuthLab\Application\Totp\TotpEnrollmentService;
use ModernAuthLab\Http\Response;
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
    /**
     * @param AuthSession $session Current authentication session facade.
     * @param TotpEnrollmentService $enrollment TOTP enrollment application service.
     */
    public function __construct(
        private AuthSession $session,
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
        ));
    }

    private function renderSetupPage(string $provisioningUri, string $secretBase32, bool $created): string
    {
        $escapedUri = htmlspecialchars($provisioningUri, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        $escapedSecret = htmlspecialchars($secretBase32, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        $status = $created ? 'New pending TOTP enrollment created.' : 'Pending TOTP enrollment resumed.';

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
                        <section aria-labelledby="provisioning-uri-title">
                            <h2 id="provisioning-uri-title">Provisioning URI</h2>
                            <textarea readonly rows="6" cols="80">{$escapedUri}</textarea>
                        </section>
                        <section aria-labelledby="manual-secret-title">
                            <h2 id="manual-secret-title">Manual Secret</h2>
                            <code>{$escapedSecret}</code>
                        </section>
                        <p>QR code rendering and first-code confirmation are intentionally handled in the next step.</p>
                        <p><a href="/account">Back to account</a></p>
                    </main>
                </body>
            </html>
            HTML;
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
}
