<?php

declare(strict_types=1);

namespace ModernAuthLab\Http\Controller;

use Closure;
use JsonException;
use ModernAuthLab\Application\Security\SecurityEventLogger;
use ModernAuthLab\Application\WebAuthn\PasskeyAuthenticationChallengeService;
use ModernAuthLab\Application\WebAuthn\PasskeyAuthenticationVerificationService;
use ModernAuthLab\Domain\Security\SecurityEventType;
use ModernAuthLab\Domain\User\User;
use ModernAuthLab\Http\Response;
use ModernAuthLab\Infrastructure\Persistence\UserRepository;
use ModernAuthLab\Security\WebAuthn\Base64Url;
use ModernAuthLab\Session\AuthSession;
use ModernAuthLab\Session\PendingMfaMethod;
use Throwable;

/**
 * Handles the Passkey step of the Password + Passkey login flow.
 *
 * The controller only accepts requests whose session is `MfaPending` with
 * `PendingMfaMethod::Passkey`. It exposes a challenge page, a JSON endpoint
 * returning the browser request options, and a JSON verification endpoint
 * that promotes the session to fully authenticated on success.
 */
final readonly class PasskeyLoginController
{
    /**
     * @param AuthSession $session Current authentication session facade.
     * @param UserRepository $users User persistence lookup.
     * @param PasskeyAuthenticationChallengeService $challengeService Authentication challenge generator.
     * @param PasskeyAuthenticationVerificationService $verificationService Assertion verification workflow.
     * @param SecurityEventLogger $securityEvents Audit logger for Passkey authentication events.
     * @param string $clientIp Server-observed client IP.
     * @param Closure(): void $rotateSessionId Session id rotation callback.
     */
    public function __construct(
        private AuthSession $session,
        private UserRepository $users,
        private PasskeyAuthenticationChallengeService $challengeService,
        private PasskeyAuthenticationVerificationService $verificationService,
        private SecurityEventLogger $securityEvents,
        private string $clientIp,
        private Closure $rotateSessionId,
    ) {}

    /**
     * Render the Passkey challenge page for the pending user.
     *
     * @return Response HTML challenge page or redirect for non-eligible sessions.
     */
    public function show(): Response
    {
        if (! $this->sessionExpectsPasskey()) {
            return Response::redirect('/login');
        }

        return Response::html($this->renderPage());
    }

    /**
     * Return the Passkey authentication options for the pending user.
     *
     * @return Response JSON `publicKey` request options or generic failure.
     */
    public function challenge(): Response
    {
        $user = $this->pendingUser();

        if ($user === null) {
            return Response::json(['error' => 'unauthorized'], 401);
        }

        try {
            $result = $this->challengeService->start($user);
        } catch (Throwable) {
            return Response::json(['error' => 'unavailable'], 400);
        }

        return Response::json(['publicKey' => $result->publicKeyOptions]);
    }

    /**
     * Verify a browser assertion and promote the session to fully authenticated.
     *
     * @param array<string, mixed> $body Decoded JSON request body.
     *
     * @return Response JSON success or generic failure.
     */
    public function verify(array $body): Response
    {
        $user = $this->pendingUser();

        if ($user === null) {
            return Response::json(['error' => 'unauthorized'], 401);
        }

        $assertion = $body['credential'] ?? $body['assertion'] ?? null;

        if (! is_array($assertion)) {
            $this->recordFailure($user);

            return Response::json(['error' => 'invalid_payload'], 400);
        }

        $challenge = $this->extractChallenge($assertion);

        if ($challenge === null) {
            $this->recordFailure($user);

            return Response::json(['error' => 'invalid_payload'], 400);
        }

        try {
            $this->verificationService->verify($user->id, $challenge, $assertion);
        } catch (Throwable) {
            $this->recordFailure($user);

            return Response::json(['error' => 'verification_failed'], 400);
        }

        $this->session->markFullyAuthenticated($user->id, $user->email);
        ($this->rotateSessionId)();
        $this->securityEvents->record(
            SecurityEventType::PasskeyAuthenticationSucceeded,
            $user->id,
            $user->email,
            $this->clientIp,
        );

        return Response::json(['status' => 'ok', 'redirect' => '/account']);
    }

    private function pendingUser(): ?User
    {
        if (! $this->sessionExpectsPasskey()) {
            return null;
        }

        $userId = $this->session->userId();

        if ($userId === null) {
            return null;
        }

        return $this->users->findById($userId);
    }

    private function sessionExpectsPasskey(): bool
    {
        return $this->session->state() === \ModernAuthLab\Session\AuthSessionState::MfaPending
            && $this->session->pendingMfaMethod() === PendingMfaMethod::Passkey;
    }

    private function recordFailure(User $user): void
    {
        $this->securityEvents->record(
            SecurityEventType::PasskeyAuthenticationFailed,
            $user->id,
            $user->email,
            $this->clientIp,
        );
    }

    /**
     * @param array<string, mixed> $assertion Browser assertion payload.
     */
    private function extractChallenge(array $assertion): ?string
    {
        $response = $assertion['response'] ?? null;

        if (! is_array($response)) {
            return null;
        }

        $clientDataJson = $response['clientDataJSON'] ?? null;

        if (! is_string($clientDataJson) || $clientDataJson === '') {
            return null;
        }

        try {
            $decoded = Base64Url::decode($clientDataJson);
            /** @var array<string, mixed> $clientData */
            $clientData = json_decode($decoded, true, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException|\InvalidArgumentException) {
            return null;
        }

        $challenge = $clientData['challenge'] ?? null;

        return is_string($challenge) && $challenge !== '' ? $challenge : null;
    }

    private function renderPage(): string
    {
        return <<<'HTML'
            <!doctype html>
            <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Passkey Login - Modern Auth Lab</title>
                </head>
                <body>
                    <main>
                        <h1>Passkey Login</h1>
                        <p>Approve the Passkey prompt to finish signing in.</p>
                        <button type="button" id="passkey-login-trigger">Use Passkey</button>
                        <p id="passkey-login-status" role="status"></p>
                    </main>
                    <script type="module" src="/assets/js/main.js"></script>
                </body>
            </html>
            HTML;
    }
}
