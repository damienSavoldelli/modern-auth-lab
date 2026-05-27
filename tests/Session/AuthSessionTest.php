<?php

declare(strict_types=1);

namespace ModernAuthLab\Tests\Session;

use ModernAuthLab\Session\AuthSession;
use ModernAuthLab\Session\AuthSessionState;
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

    public function testTracksFullyAuthenticatedState(): void
    {
        $storage = [];
        $session = new AuthSession($storage);

        $session->markFullyAuthenticated();

        self::assertSame(AuthSessionState::FullyAuthenticated, $session->state());
        self::assertTrue($session->state()->isFullyAuthenticated());
    }

    public function testClearsAuthenticationState(): void
    {
        $storage = ['auth_state' => 'fully_authenticated'];
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
