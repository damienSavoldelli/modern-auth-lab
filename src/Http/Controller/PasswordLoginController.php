<?php

declare(strict_types=1);

namespace ModernAuthLab\Http\Controller;

use Closure;
use ModernAuthLab\Application\Auth\PasswordAuthenticator;
use ModernAuthLab\Application\Security\SecurityEventLogger;
use ModernAuthLab\Domain\Security\SecurityEventType;
use ModernAuthLab\Http\Response;
use ModernAuthLab\Security\Csrf\CsrfTokenException;
use ModernAuthLab\Security\Csrf\CsrfTokenManager;
use ModernAuthLab\Security\RateLimit\LoginRateLimiter;
use ModernAuthLab\Session\AuthSession;

/**
 * Handles the password login form and current pre-MFA full-session transition.
 *
 * This controller coordinates several security concerns at the HTTP boundary:
 * CSRF validation, login rate limiting, password verification, security event
 * logging, session state transition, and session id rotation.
 */
final readonly class PasswordLoginController
{
    private const CSRF_TOKEN_ID = 'login_form';

    /**
     * @param CsrfTokenManager $csrf CSRF token manager for login form submissions.
     * @param PasswordAuthenticator $authenticator Password verification service.
     * @param AuthSession $session Current authentication session facade.
     * @param LoginRateLimiter $rateLimiter Initial login throttling control.
     * @param SecurityEventLogger $securityEvents Audit logger for login events.
     * @param string $clientIp Server-observed client IP.
     * @param Closure(): void $rotateSessionId
     */
    public function __construct(
        private CsrfTokenManager $csrf,
        private PasswordAuthenticator $authenticator,
        private AuthSession $session,
        private LoginRateLimiter $rateLimiter,
        private SecurityEventLogger $securityEvents,
        private string $clientIp,
        private Closure $rotateSessionId,
    ) {}

    /**
     * Render a fresh login form with a CSRF token.
     *
     * @return Response Login form response.
     */
    public function show(): Response
    {
        $token = $this->csrf->issue(self::CSRF_TOKEN_ID);

        return Response::html($this->renderForm($token->value));
    }

    /**
     * Process password login submission.
     *
     * Successful password authentication currently creates a full session only
     * because this is the pre-MFA milestone. Later MFA flows will split password
     * verification from final authentication again.
     *
     * @param array<string, mixed> $post
     *
     * @return Response Redirect on success or generic failure response.
     */
    public function submit(array $post): Response
    {
        try {
            $this->csrf->consume(self::CSRF_TOKEN_ID, $this->stringValue($post['csrf_token'] ?? null));
        } catch (CsrfTokenException) {
            return $this->failedLoginResponse();
        }

        $email = $this->stringValue($post['email'] ?? null);
        // The limiter key combines the submitted account identifier with the
        // server-observed IP. It must not reveal raw email addresses in session
        // storage, so the final key is hashed below.
        $rateLimitIdentifier = $this->rateLimitIdentifier($email);

        if (! $this->rateLimiter->isAllowed($rateLimitIdentifier)) {
            return $this->failedLoginResponse(429);
        }

        $result = $this->authenticator->authenticate(
            $email,
            $this->stringValue($post['password'] ?? null),
        );

        if (! $result->success) {
            $this->rateLimiter->recordFailure($rateLimitIdentifier);
            $this->securityEvents->record(
                SecurityEventType::PasswordLoginFailed,
                null,
                $email,
                $this->clientIp,
            );

            return $this->failedLoginResponse();
        }

        $this->rateLimiter->clear($rateLimitIdentifier);
        $this->securityEvents->record(
            SecurityEventType::PasswordLoginSucceeded,
            $result->user?->id,
            $result->user?->email,
            $this->clientIp,
        );
        $this->session->markFullyAuthenticated();
        ($this->rotateSessionId)();

        return Response::redirect('/account');
    }

    /**
     * Re-render the login form with the generic failure message.
     *
     * The same message is used for invalid credentials and rate-limited attempts
     * to avoid leaking account or policy state through the UI.
     *
     * @param int $statusCode HTTP status code to return.
     *
     * @return Response Login form with generic failure message.
     */
    private function failedLoginResponse(int $statusCode = 401): Response
    {
        $token = $this->csrf->issue(self::CSRF_TOKEN_ID);

        return Response::html(
            $this->renderForm($token->value, 'Invalid credentials.'),
            $statusCode,
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
                    <title>Login - Modern Auth Lab</title>
                </head>
                <body>
                    <main>
                        <h1>Login</h1>
                        {$errorHtml}
                        <form method="post" action="/login">
                            <input type="hidden" name="csrf_token" value="{$escapedToken}">
                            <label>
                                Email
                                <input type="email" name="email" autocomplete="username" required>
                            </label>
                            <label>
                                Password
                                <input type="password" name="password" autocomplete="current-password" required>
                            </label>
                            <button type="submit">Continue</button>
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

    private function rateLimitIdentifier(string $email): string
    {
        return hash('sha256', strtolower(trim($email)) . '|' . $this->clientIp);
    }
}
