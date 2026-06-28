<?php

declare(strict_types=1);

namespace ModernAuthLab\Http\Controller;

use Closure;
use ModernAuthLab\Application\Security\SecurityEventLogger;
use ModernAuthLab\Domain\Security\SecurityEventType;
use ModernAuthLab\Http\Response;
use ModernAuthLab\Security\Csrf\CsrfTokenException;
use ModernAuthLab\Security\Csrf\CsrfTokenManager;
use ModernAuthLab\Session\AuthSession;

/**
 * Handles CSRF-protected logout.
 *
 * Logout changes server-side authentication state, so it is modeled as a POST
 * action with CSRF validation rather than a GET link.
 */
final readonly class LogoutController
{
    private const CSRF_TOKEN_ID = 'logout_form';

    /**
     * @param AuthSession $session Current authentication session facade.
     * @param CsrfTokenManager $csrf CSRF token manager for logout validation.
     * @param SecurityEventLogger $securityEvents Audit logger for logout events.
     * @param string $clientIp Server-observed client IP.
     * @param Closure(): void $destroySession
     */
    public function __construct(
        private AuthSession $session,
        private CsrfTokenManager $csrf,
        private SecurityEventLogger $securityEvents,
        private string $clientIp,
        private Closure $destroySession,
    ) {}

    /**
     * Validate logout intent, record the security event, and destroy the session.
     *
     * @param array<string, mixed> $post
     *
     * @return Response Redirect after logout or invalid logout response.
     */
    public function submit(array $post): Response
    {
        try {
            $this->csrf->consume(self::CSRF_TOKEN_ID, $this->stringValue($post['csrf_token'] ?? null));
        } catch (CsrfTokenException) {
            $this->securityEvents->record(
                SecurityEventType::LogoutCsrfFailed,
                null,
                null,
                $this->clientIp,
            );

            return Response::html('Invalid logout request.', 400);
        }

        $this->securityEvents->record(
            SecurityEventType::LogoutSucceeded,
            null,
            null,
            $this->clientIp,
        );
        $this->session->clearAuthentication();
        ($this->destroySession)();

        return Response::redirect('/login');
    }

    private function stringValue(mixed $value): string
    {
        return is_string($value) ? $value : '';
    }
}
