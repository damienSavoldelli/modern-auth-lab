<?php

declare(strict_types=1);

namespace ModernAuthLab\Tests\Security\WebAuthn;

use ModernAuthLab\Security\WebAuthn\Base64Url;
use PHPUnit\Framework\TestCase;

final class Base64UrlTest extends TestCase
{
    public function testEncodesWithoutPaddingOrUnsafeUrlCharacters(): void
    {
        $encoded = Base64Url::encode("\xfb\xff\x00");

        self::assertSame('-_8A', $encoded);
        self::assertStringNotContainsString('+', $encoded);
        self::assertStringNotContainsString('/', $encoded);
        self::assertStringNotContainsString('=', $encoded);
    }

    public function testDecodesBase64UrlValue(): void
    {
        self::assertSame("\xfb\xff\x00", Base64Url::decode('-_8A'));
    }

    public function testRejectsEmptyValue(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        Base64Url::decode('');
    }

    public function testRejectsInvalidCharacters(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        Base64Url::decode('not+url-safe');
    }
}
