<?php

declare(strict_types=1);

namespace ModernAuthLab\Http\Controller;

use ModernAuthLab\Http\Response;
use ModernAuthLab\Infrastructure\Persistence\UserTotpCredential;
use ModernAuthLab\Infrastructure\Persistence\UserTotpCredentialRepository;
use ModernAuthLab\Session\AuthSession;

/**
 * Displays the authenticated account security overview.
 *
 * This controller intentionally exposes only lifecycle status and operational
 * metadata. TOTP secret material, provisioning URIs, QR codes, and encrypted
 * payload fields must never be rendered on this page.
 */
final readonly class AccountSecurityController
{
    /**
     * Receive the current auth session and TOTP credential repository.
     *
     * @param AuthSession $session Current authentication session facade.
     * @param UserTotpCredentialRepository $totpCredentials Repository used to read TOTP lifecycle state.
     */
    public function __construct(
        private AuthSession $session,
        private UserTotpCredentialRepository $totpCredentials,
    ) {}

    /**
     * Show the account security page or redirect non-authenticated sessions.
     *
     * @return Response Protected account security page or login redirect.
     */
    public function show(): Response
    {
        if (! $this->session->state()->isFullyAuthenticated()) {
            return Response::redirect('/login');
        }

        $userId = $this->session->userId();

        if ($userId === null) {
            return Response::redirect('/login');
        }

        $activeTotpCredential = $this->totpCredentials->findActiveByUserId($userId);

        return Response::html($this->renderPage($activeTotpCredential));
    }

    /**
     * Render the read-only account security page.
     *
     * @param UserTotpCredential|null $activeTotpCredential Active TOTP credential when one exists.
     *
     * @return string HTML response body.
     */
    private function renderPage(?UserTotpCredential $activeTotpCredential): string
    {
        $totpStatus = $activeTotpCredential === null ? 'Disabled' : 'Enabled';
        $totpDetails = $activeTotpCredential === null
            ? '<p>TOTP is not active for this account.</p><p><a href="/account/totp/setup">Set up TOTP</a></p>'
            : $this->renderActiveTotpDetails($activeTotpCredential);

        return <<<HTML
            <!doctype html>
            <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Account Security - Modern Auth Lab</title>
                </head>
                <body>
                    <main>
                        <h1>Account Security</h1>
                        <section aria-labelledby="totp-status">
                            <h2 id="totp-status">TOTP</h2>
                            <p>Status: {$totpStatus}</p>
                            {$totpDetails}
                        </section>
                        <p><a href="/account">Back to account</a></p>
                    </main>
                </body>
            </html>
            HTML;
    }

    /**
     * Render safe metadata for an active TOTP credential.
     *
     * The secret ciphertext, nonce, key id, and provisioning URI are intentionally
     * omitted because this page is only a lifecycle overview.
     *
     * @param UserTotpCredential $credential Active TOTP credential.
     *
     * @return string HTML fragment.
     */
    private function renderActiveTotpDetails(UserTotpCredential $credential): string
    {
        $algorithm = htmlspecialchars($credential->algorithm, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        $confirmedAt = htmlspecialchars($credential->confirmedAt ?? 'Unknown', ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        $lastUsedTimeStep = $credential->lastUsedTimeStep === null
            ? 'Never used'
            : (string) $credential->lastUsedTimeStep;

        return <<<HTML
            <p>TOTP is active for this account.</p>
            <dl>
                <dt>Algorithm</dt>
                <dd>{$algorithm}</dd>
                <dt>Digits</dt>
                <dd>{$credential->digits}</dd>
                <dt>Period</dt>
                <dd>{$credential->period} seconds</dd>
                <dt>Confirmed at</dt>
                <dd>{$confirmedAt}</dd>
                <dt>Last accepted time step</dt>
                <dd>{$lastUsedTimeStep}</dd>
            </dl>
            HTML;
    }
}
