<?php

declare(strict_types=1);

namespace ModernAuthLab\Tests\Session;

use ModernAuthLab\Session\AuthSession;
use ModernAuthLab\Session\AuthSessionState;
use ModernAuthLab\Session\PendingMfaMethod;
use PHPUnit\Framework\TestCase;

final class AuthSessionTest extends TestCase
{
    public function testDefaultsToAnonymousState(): void
    {
        $storage = [];
        $session = new AuthSession($storage);

        self::assertSame(AuthSessionState::Anonymous, $session->state());
    }

    public function testTracksPasswordVerifiedState(): void
    {
        $storage = [];
        $session = new AuthSession($storage);

        $session->markPasswordVerified();

        self::assertSame(AuthSessionState::PasswordVerified, $session->state());
        self::assertSame(['auth_state' => 'password_verified'], $storage);
    }

    public function testTracksMfaPendingState(): void
    {
        $storage = [];
        $session = new AuthSession($storage);

        $session->markMfaPending();

        self::assertSame(AuthSessionState::MfaPending, $session->state());
    }

    public function testTracksMfaPendingStateWithVerifiedUserIdentity(): void
    {
        $storage = [];
        $session = new AuthSession($storage);

        $session->markMfaPending(123, 'user@example.com');

        self::assertSame(AuthSessionState::MfaPending, $session->state());
        self::assertSame(123, $session->userId());
        self::assertSame('user@example.com', $session->userEmail());
        self::assertSame([
            'auth_state' => 'mfa_pending',
            'auth_user_id' => 123,
            'auth_user_email' => 'user@example.com',
        ], $storage);
    }

    public function testTracksPendingMfaMethodWhenProvided(): void
    {
        $storage = [];
        $session = new AuthSession($storage);

        $session->markMfaPending(123, 'user@example.com', PendingMfaMethod::Passkey);

        self::assertSame(PendingMfaMethod::Passkey, $session->pendingMfaMethod());
        self::assertSame([
            'auth_state' => 'mfa_pending',
            'auth_user_id' => 123,
            'auth_user_email' => 'user@example.com',
            'auth_pending_mfa_method' => 'passkey',
        ], $storage);
    }

    public function testPendingMfaMethodDefaultsToNull(): void
    {
        $storage = [];
        $session = new AuthSession($storage);

        $session->markMfaPending(123, 'user@example.com');

        self::assertNull($session->pendingMfaMethod());
    }

    public function testInvalidStoredPendingMfaMethodReturnsNull(): void
    {
        $storage = ['auth_pending_mfa_method' => 'unexpected'];
        $session = new AuthSession($storage);

        self::assertNull($session->pendingMfaMethod());
    }

    public function testClearAuthenticationRemovesPendingMfaMethod(): void
    {
        $storage = [
            'auth_state' => 'mfa_pending',
            'auth_user_id' => 123,
            'auth_user_email' => 'user@example.com',
            'auth_pending_mfa_method' => 'passkey',
        ];
        $session = new AuthSession($storage);

        $session->clearAuthentication();

        self::assertNull($session->pendingMfaMethod());
        self::assertSame([], $storage);
    }

    public function testTracksFullyAuthenticatedState(): void
    {
        $storage = [];
        $session = new AuthSession($storage);

        $session->markFullyAuthenticated(123, 'user@example.com');

        self::assertSame(AuthSessionState::FullyAuthenticated, $session->state());
        self::assertTrue($session->state()->isFullyAuthenticated());
        self::assertSame(123, $session->userId());
        self::assertSame('user@example.com', $session->userEmail());
    }

    public function testIgnoresInvalidStoredUserIdentity(): void
    {
        $storage = [
            'auth_user_id' => '123',
            'auth_user_email' => '',
        ];
        $session = new AuthSession($storage);

        self::assertNull($session->userId());
        self::assertNull($session->userEmail());
    }

    public function testClearsAuthenticationState(): void
    {
        $storage = [
            'auth_state' => 'fully_authenticated',
            'auth_user_id' => 123,
            'auth_user_email' => 'user@example.com',
        ];
        $session = new AuthSession($storage);

        $session->clearAuthentication();

        self::assertSame(AuthSessionState::Anonymous, $session->state());
        self::assertSame([], $storage);
    }

    public function testInvalidStoredStateFallsBackToAnonymous(): void
    {
        $storage = ['auth_state' => 'unexpected_state'];
        $session = new AuthSession($storage);

        self::assertSame(AuthSessionState::Anonymous, $session->state());
    }
}
