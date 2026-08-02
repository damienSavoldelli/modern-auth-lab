<?php

declare(strict_types=1);

namespace ModernAuthLab\Http\Controller;

use ModernAuthLab\Application\Security\SecurityEventLogger;
use ModernAuthLab\Application\Totp\TotpDisableService;
use ModernAuthLab\Application\Totp\TotpLoginVerificationService;
use ModernAuthLab\Application\Totp\TotpRecoveryCodeService;
use ModernAuthLab\Domain\Security\SecurityEventType;
use ModernAuthLab\Http\Response;
use ModernAuthLab\Infrastructure\Persistence\UserPasskeyCredential;
use ModernAuthLab\Infrastructure\Persistence\UserPasskeyCredentialRepository;
use ModernAuthLab\Infrastructure\Persistence\UserTotpCredential;
use ModernAuthLab\Infrastructure\Persistence\UserTotpCredentialRepository;
use ModernAuthLab\Security\Csrf\CsrfTokenException;
use ModernAuthLab\Security\Csrf\CsrfTokenManager;
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
    private const TOTP_DISABLE_CSRF_TOKEN_ID = 'totp_disable_form';
    private const TOTP_RECOVERY_CODES_CSRF_TOKEN_ID = 'totp_recovery_codes_form';

    /**
     * Receive the current auth session and credential repositories.
     *
     * @param AuthSession $session Current authentication session facade.
     * @param UserTotpCredentialRepository $totpCredentials Repository used to read TOTP lifecycle state.
     * @param UserPasskeyCredentialRepository $passkeyCredentials Repository used to read Passkey lifecycle state.
     * @param CsrfTokenManager $csrf CSRF token manager for future security-setting mutations.
     */
    public function __construct(
        private AuthSession $session,
        private UserTotpCredentialRepository $totpCredentials,
        private UserPasskeyCredentialRepository $passkeyCredentials,
        private CsrfTokenManager $csrf,
    ) {}

    /**
     * Show the account security page or redirect non-authenticated sessions.
     *
     * @return Response Protected account security page or login redirect.
     */
    public function show(): Response
    {
        $redirect = $this->redirectWhenSessionCannotManageSecurity();
        if ($redirect !== null) {
            return $redirect;
        }

        $userId = $this->session->userId();
        \assert($userId !== null);
        $activeTotpCredential = $this->totpCredentials->findActiveByUserId($userId);
        $activePasskeyCredentials = $this->passkeyCredentials->findActiveByUserId($userId);

        return Response::html($this->renderPage($activeTotpCredential, $activePasskeyCredentials));
    }

    /**
     * Process a normal TOTP disable request.
     *
     * @param array<string, mixed> $post Submitted form data.
     * @param TotpDisableService $disableService TOTP disable application workflow.
     * @param SecurityEventLogger $securityEvents Audit logger for lifecycle events.
     * @param string $clientIp Server-observed client IP.
     *
     * @return Response Redirect after success or generic failure response.
     */
    public function disableTotp(
        array $post,
        TotpDisableService $disableService,
        SecurityEventLogger $securityEvents,
        string $clientIp,
    ): Response {
        $redirect = $this->redirectWhenSessionCannotManageSecurity();
        if ($redirect !== null) {
            return $redirect;
        }

        $userId = $this->session->userId();
        $email = $this->session->userEmail();

        if ($userId === null || $email === null) {
            return Response::redirect('/login');
        }

        try {
            $this->csrf->consume(self::TOTP_DISABLE_CSRF_TOKEN_ID, $this->stringValue($post['csrf_token'] ?? null));
        } catch (CsrfTokenException) {
            $securityEvents->record(
                SecurityEventType::TotpDisableFailed,
                $userId,
                $email,
                $clientIp,
            );

            return $this->failedDisableResponse();
        }

        $disabled = $disableService->disable($userId, $this->stringValue($post['code'] ?? null));

        if (! $disabled) {
            $securityEvents->record(
                SecurityEventType::TotpDisableFailed,
                $userId,
                $email,
                $clientIp,
            );

            return $this->failedDisableResponse();
        }

        $securityEvents->record(
            SecurityEventType::TotpDisableSucceeded,
            $userId,
            $email,
            $clientIp,
        );

        return Response::redirect('/account/security');
    }

    /**
     * Generate a new recovery-code set after fresh TOTP possession proof.
     *
     * @param array<string, mixed> $post Submitted form data.
     * @param TotpLoginVerificationService $verification TOTP verifier for current-code proof.
     * @param TotpRecoveryCodeService $recoveryCodes Recovery-code generation workflow.
     * @param SecurityEventLogger $securityEvents Audit logger for recovery-code events.
     * @param string $clientIp Server-observed client IP.
     *
     * @return Response Page containing one-time display codes or generic failure.
     */
    public function generateRecoveryCodes(
        array $post,
        TotpLoginVerificationService $verification,
        TotpRecoveryCodeService $recoveryCodes,
        SecurityEventLogger $securityEvents,
        string $clientIp,
    ): Response {
        $redirect = $this->redirectWhenSessionCannotManageSecurity();
        if ($redirect !== null) {
            return $redirect;
        }

        $userId = $this->session->userId();
        $email = $this->session->userEmail();

        if ($userId === null || $email === null) {
            return Response::redirect('/login');
        }

        try {
            $this->csrf->consume(
                self::TOTP_RECOVERY_CODES_CSRF_TOKEN_ID,
                $this->stringValue($post['csrf_token'] ?? null),
            );
        } catch (CsrfTokenException) {
            $securityEvents->record(
                SecurityEventType::TotpRecoveryCodesGenerationFailed,
                $userId,
                $email,
                $clientIp,
            );

            return $this->failedRecoveryCodeGenerationResponse();
        }

        $verificationResult = $verification->verify($userId, $this->stringValue($post['code'] ?? null));

        if (! $verificationResult->success) {
            $securityEvents->record(
                SecurityEventType::TotpRecoveryCodesGenerationFailed,
                $userId,
                $email,
                $clientIp,
            );

            return $this->failedRecoveryCodeGenerationResponse();
        }

        $result = $recoveryCodes->generateForUser($userId);
        $securityEvents->record(
            SecurityEventType::TotpRecoveryCodesGenerated,
            $userId,
            $email,
            $clientIp,
        );

        return Response::html($this->renderPage(
            $this->totpCredentials->findActiveByUserId($userId),
            $this->passkeyCredentials->findActiveByUserId($userId),
            recoveryCodes: $result->plainCodes,
        ));
    }

    private function redirectWhenSessionCannotManageSecurity(): ?Response
    {
        if (! $this->session->state()->isFullyAuthenticated() || $this->session->userId() === null) {
            return Response::redirect('/login');
        }

        return null;
    }

    private function failedDisableResponse(): Response
    {
        $userId = $this->session->userId();
        $activeTotpCredential = $userId === null ? null : $this->totpCredentials->findActiveByUserId($userId);
        $activePasskeyCredentials = $userId === null ? [] : $this->passkeyCredentials->findActiveByUserId($userId);

        return Response::html(
            $this->renderPage(
                $activeTotpCredential,
                $activePasskeyCredentials,
                'Unable to disable TOTP with the submitted authenticator code.',
            ),
            400,
        );
    }

    private function failedRecoveryCodeGenerationResponse(): Response
    {
        $userId = $this->session->userId();
        $activeTotpCredential = $userId === null ? null : $this->totpCredentials->findActiveByUserId($userId);
        $activePasskeyCredentials = $userId === null ? [] : $this->passkeyCredentials->findActiveByUserId($userId);

        return Response::html(
            $this->renderPage(
                $activeTotpCredential,
                $activePasskeyCredentials,
                'Unable to generate recovery codes with the submitted authenticator code.',
            ),
            400,
        );
    }

    /**
     * Render the read-only account security page.
     *
     * @param UserTotpCredential|null $activeTotpCredential Active TOTP credential when one exists.
     * @param list<UserPasskeyCredential> $activePasskeyCredentials Active Passkey credentials for this user.
     * @param string|null $error User-facing generic lifecycle error.
     * @param list<string> $recoveryCodes Plain recovery codes for one-time display.
     *
     * @return string HTML response body.
     */
    private function renderPage(
        ?UserTotpCredential $activeTotpCredential,
        array $activePasskeyCredentials,
        ?string $error = null,
        array $recoveryCodes = [],
    ): string {
        $totpStatus = $activeTotpCredential === null ? 'Disabled' : 'Enabled';
        $totpDetails = $activeTotpCredential === null
            ? '<p>TOTP is not active for this account.</p><p><a href="/account/totp/setup">Set up TOTP</a></p>'
            : $this->renderActiveTotpDetails($activeTotpCredential);
        $errorHtml = $error === null
            ? ''
            : '<p role="alert">' . htmlspecialchars($error, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '</p>';
        $recoveryCodesHtml = $this->renderRecoveryCodes($recoveryCodes);
        $passkeysHtml = $this->renderPasskeys($activePasskeyCredentials);

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
                        {$errorHtml}
                        {$recoveryCodesHtml}
                        <section aria-labelledby="totp-status">
                            <h2 id="totp-status">TOTP</h2>
                            <p>Status: {$totpStatus}</p>
                            {$totpDetails}
                        </section>
                        {$passkeysHtml}
                        <p><a href="/account">Back to account</a></p>
                    </main>
                </body>
            </html>
            HTML;
    }

    /**
     * Render the Passkeys section listing enrolled credentials and the enrollment form.
     *
     * The credential id, public key, and sign counter must never appear here. The section
     * only exposes user-facing metadata (name, last used timestamp) so this page remains a
     * safe overview.
     *
     * @param list<UserPasskeyCredential> $credentials Active Passkey credentials.
     *
     * @return string HTML section fragment.
     */
    private function renderPasskeys(array $credentials): string
    {
        $listHtml = $credentials === []
            ? '<p>No Passkey is currently registered for this account.</p>'
            : $this->renderPasskeysList($credentials);

        return <<<HTML
            <section aria-labelledby="passkeys">
                <h2 id="passkeys">Passkeys</h2>
                {$listHtml}
                <form id="passkey-enrollment-form">
                    <label>
                        Passkey name
                        <input type="text" name="name" id="passkey-name" maxlength="80" required>
                    </label>
                    <button type="submit" id="passkey-enrollment-submit">Add Passkey</button>
                </form>
            </section>
            HTML;
    }

    /**
     * Render the list of currently enrolled Passkeys.
     *
     * @param list<UserPasskeyCredential> $credentials Active Passkey credentials.
     *
     * @return string HTML list fragment.
     */
    private function renderPasskeysList(array $credentials): string
    {
        $items = '';

        foreach ($credentials as $credential) {
            $name = htmlspecialchars($credential->name, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
            $lastUsed = $credential->lastUsedAt === null
                ? 'Never used'
                : htmlspecialchars($credential->lastUsedAt, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
            $items .= "<li><strong>{$name}</strong> — last used: {$lastUsed}</li>";
        }

        return "<ul>{$items}</ul>";
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
        $disableCsrfToken = htmlspecialchars(
            $this->csrf->issue(self::TOTP_DISABLE_CSRF_TOKEN_ID)->value,
            ENT_QUOTES | ENT_SUBSTITUTE,
            'UTF-8',
        );
        $recoveryCodesCsrfToken = htmlspecialchars(
            $this->csrf->issue(self::TOTP_RECOVERY_CODES_CSRF_TOKEN_ID)->value,
            ENT_QUOTES | ENT_SUBSTITUTE,
            'UTF-8',
        );

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
            <form method="post" action="/account/security/totp/disable">
                <input type="hidden" name="csrf_token" value="{$disableCsrfToken}">
                <label>
                    Current authenticator code
                    <input type="text" name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" required>
                </label>
                <button type="submit">Disable TOTP</button>
            </form>
            <form method="post" action="/account/security/totp/recovery-codes/generate">
                <input type="hidden" name="csrf_token" value="{$recoveryCodesCsrfToken}">
                <label>
                    Current authenticator code
                    <input type="text" name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" required>
                </label>
                <button type="submit">Generate recovery codes</button>
            </form>
            HTML;
    }

    /**
     * Render plain recovery codes immediately after generation.
     *
     * @param list<string> $recoveryCodes Plain recovery codes for one-time display.
     *
     * @return string HTML fragment.
     */
    private function renderRecoveryCodes(array $recoveryCodes): string
    {
        if ($recoveryCodes === []) {
            return '';
        }

        $items = '';

        foreach ($recoveryCodes as $recoveryCode) {
            $escapedRecoveryCode = htmlspecialchars($recoveryCode, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
            $items .= "<li><code>{$escapedRecoveryCode}</code></li>";
        }

        return <<<HTML
            <section aria-labelledby="recovery-codes">
                <h2 id="recovery-codes">Recovery Codes</h2>
                <p>Save these codes now. They will not be shown again.</p>
                <ol>
                    {$items}
                </ol>
            </section>
            HTML;
    }

    private function stringValue(mixed $value): string
    {
        return is_string($value) ? $value : '';
    }
}
