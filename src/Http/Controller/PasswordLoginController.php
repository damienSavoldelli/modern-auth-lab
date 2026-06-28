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

final readonly class PasswordLoginController
{
    private const CSRF_TOKEN_ID = 'login_form';

    /**
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

    public function show(): Response
    {
        $token = $this->csrf->issue(self::CSRF_TOKEN_ID);

        return Response::html($this->renderForm($token->value));
    }

    /**
     * @param array<string, mixed> $post
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
