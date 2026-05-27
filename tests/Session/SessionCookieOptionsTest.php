<?php

declare(strict_types=1);

namespace ModernAuthLab\Tests\Session;

use InvalidArgumentException;
use ModernAuthLab\Session\SessionCookieOptions;
use PHPUnit\Framework\TestCase;

final class SessionCookieOptionsTest extends TestCase
{
    public function testCreatesSecureHttpOnlyCookieOptionsByDefault(): void
    {
        $options = new SessionCookieOptions();

        self::assertSame('modern_auth_lab_session', $options->name);
        self::assertSame([
            'lifetime' => 0,
            'path' => '/',
            'domain' => '',
            'secure' => true,
            'httponly' => true,
            'samesite' => 'Lax',
        ], $options->toPhpCookieParams());
    }

    public function testCreatesRequestAwareOptionsForLocalHttpDevelopment(): void
    {
        $options = SessionCookieOptions::forRequest(isHttps: false);

        self::assertFalse($options->secure);
        self::assertTrue($options->httpOnly);
        self::assertSame('Lax', $options->sameSite);
    }

    public function testRejectsEmptyCookieName(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Session cookie name cannot be empty.');

        new SessionCookieOptions(name: '');
    }

    public function testRejectsNegativeLifetime(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Session cookie lifetime cannot be negative.');

        new SessionCookieOptions(lifetime: -1);
    }

    public function testRejectsInvalidSameSiteValue(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Session cookie SameSite must be Lax, Strict, or None.');

        new SessionCookieOptions(sameSite: 'Invalid');
    }

    public function testRejectsSameSiteNoneWithoutSecureCookie(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Session cookie SameSite=None requires Secure.');

        new SessionCookieOptions(secure: false, sameSite: 'None');
    }
}
