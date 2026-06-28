<?php

declare(strict_types=1);

namespace ModernAuthLab\Http\Controller;

use Closure;
use ModernAuthLab\Http\Response;
use ModernAuthLab\Security\Csrf\CsrfTokenException;
use ModernAuthLab\Security\Csrf\CsrfTokenManager;
use ModernAuthLab\Session\AuthSession;

final readonly class LogoutController
{
    private const CSRF_TOKEN_ID = 'logout_form';

    /**
     * @param Closure(): void $destroySession
     */
    public function __construct(
        private AuthSession $session,
        private CsrfTokenManager $csrf,
        private Closure $destroySession,
    ) {}

    /**
     * @param array<string, mixed> $post
     */
    public function submit(array $post): Response
    {
        try {
            $this->csrf->consume(self::CSRF_TOKEN_ID, $this->stringValue($post['csrf_token'] ?? null));
        } catch (CsrfTokenException) {
            return Response::html('Invalid logout request.', 400);
        }

        $this->session->clearAuthentication();
        ($this->destroySession)();

        return Response::redirect('/login');
    }

    private function stringValue(mixed $value): string
    {
        return is_string($value) ? $value : '';
    }
}
