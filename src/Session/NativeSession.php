<?php

declare(strict_types=1);

namespace ModernAuthLab\Session;

use RuntimeException;

final class NativeSession
{
    public function configure(SessionCookieOptions $options): void
    {
        $this->assertSessionNotActive('Cannot configure session cookies after the session has started.');

        session_name($options->name);
        session_set_cookie_params($options->toPhpCookieParams());
    }

    public function start(): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            return;
        }

        if (! session_start()) {
            throw new RuntimeException('Unable to start the PHP session.');
        }
    }

    public function auth(): AuthSession
    {
        $this->start();

        return new AuthSession($_SESSION);
    }

    public function rotateId(): void
    {
        $this->assertSessionActive('Cannot rotate session ID before the session has started.');

        if (! session_regenerate_id(true)) {
            throw new RuntimeException('Unable to rotate the PHP session ID.');
        }
    }

    public function destroy(): void
    {
        $this->assertSessionActive('Cannot destroy session before the session has started.');

        $_SESSION = [];

        if (! session_destroy()) {
            throw new RuntimeException('Unable to destroy the PHP session.');
        }
    }

    private function assertSessionActive(string $message): void
    {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            throw new RuntimeException($message);
        }
    }

    private function assertSessionNotActive(string $message): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            throw new RuntimeException($message);
        }
    }
}
