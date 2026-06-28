<?php

declare(strict_types=1);

namespace ModernAuthLab\Session;

use RuntimeException;

/**
 * Wrapper around PHP's native session API.
 *
 * Native session functions are global and stateful. This wrapper keeps their
 * use explicit and gives the application one place for startup, rotation, and
 * destruction errors.
 */
final class NativeSession
{
    /**
     * Configure cookie parameters before the session starts.
     */
    public function configure(SessionCookieOptions $options): void
    {
        $this->assertSessionNotActive('Cannot configure session cookies after the session has started.');

        session_name($options->name);
        session_set_cookie_params($options->toPhpCookieParams());
    }

    /**
     * Start the PHP session if it is not already active.
     */
    public function start(): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            return;
        }

        if (! session_start()) {
            throw new RuntimeException('Unable to start the PHP session.');
        }
    }

    /**
     * Start the session and expose the authentication-state facade.
     */
    public function auth(): AuthSession
    {
        $this->start();

        return new AuthSession($_SESSION);
    }

    /**
     * Rotate the session id after an authentication privilege change.
     */
    public function rotateId(): void
    {
        $this->assertSessionActive('Cannot rotate session ID before the session has started.');

        if (! session_regenerate_id(true)) {
            throw new RuntimeException('Unable to rotate the PHP session ID.');
        }
    }

    /**
     * Destroy the active session after logout.
     */
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
