<?php

declare(strict_types=1);

namespace ModernAuthLab\Tests\Security\Csrf;

use ModernAuthLab\Security\Csrf\CsrfTokenException;
use ModernAuthLab\Security\Csrf\CsrfTokenManager;
use PHPUnit\Framework\TestCase;

final class CsrfTokenManagerTest extends TestCase
{
    public function testIssuesTokenAndStoresItById(): void
    {
        $storage = [];
        $manager = new CsrfTokenManager($storage);

        $token = $manager->issue('login_form');

        self::assertSame('login_form', $token->id);
        self::assertMatchesRegularExpression('/^[a-f0-9]{64}$/', $token->value);
        self::assertSame($token->value, $storage['_csrf_tokens']['login_form']);
    }

    public function testValidatesIssuedToken(): void
    {
        $storage = [];
        $manager = new CsrfTokenManager($storage);
        $token = $manager->issue('login_form');

        $manager->validate('login_form', $token->value);

        self::assertSame($token->value, $storage['_csrf_tokens']['login_form']);
    }

    public function testConsumeValidTokenRemovesIt(): void
    {
        $storage = [];
        $manager = new CsrfTokenManager($storage);
        $token = $manager->issue('login_form');

        $manager->consume('login_form', $token->value);

        self::assertSame([], $storage['_csrf_tokens']);
    }

    public function testRejectsMissingToken(): void
    {
        $storage = [];
        $manager = new CsrfTokenManager($storage);

        $this->expectException(CsrfTokenException::class);
        $this->expectExceptionMessage('CSRF token "login_form" is missing.');

        $manager->validate('login_form', null);
    }

    public function testRejectsEmptySubmittedToken(): void
    {
        $storage = [];
        $manager = new CsrfTokenManager($storage);
        $manager->issue('login_form');

        $this->expectException(CsrfTokenException::class);
        $this->expectExceptionMessage('CSRF token "login_form" is missing.');

        $manager->validate('login_form', '');
    }

    public function testRejectsInvalidToken(): void
    {
        $storage = [];
        $manager = new CsrfTokenManager($storage);
        $manager->issue('login_form');

        $this->expectException(CsrfTokenException::class);
        $this->expectExceptionMessage('CSRF token "login_form" is invalid.');

        $manager->validate('login_form', str_repeat('0', 64));
    }

    public function testRejectsEmptyTokenId(): void
    {
        $storage = [];
        $manager = new CsrfTokenManager($storage);

        $this->expectException(CsrfTokenException::class);
        $this->expectExceptionMessage('CSRF token id cannot be empty.');

        $manager->issue('');
    }

    public function testClearRemovesAllTokens(): void
    {
        $storage = [];
        $manager = new CsrfTokenManager($storage);
        $manager->issue('login_form');
        $manager->issue('profile_form');

        $manager->clear();

        self::assertSame([], $storage);
    }
}
