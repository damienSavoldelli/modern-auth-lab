<?php

declare(strict_types=1);

namespace ModernAuthLab\Tests\Security\Totp;

use InvalidArgumentException;
use ModernAuthLab\Security\Totp\Base32;
use PHPUnit\Framework\TestCase;

final class Base32Test extends TestCase
{
    public function testEncodesKnownRfc4648VectorsWithoutPadding(): void
    {
        self::assertSame('', Base32::encode(''));
        self::assertSame('MY', Base32::encode('f'));
        self::assertSame('MZXQ', Base32::encode('fo'));
        self::assertSame('MZXW6', Base32::encode('foo'));
        self::assertSame('MZXW6YQ', Base32::encode('foob'));
        self::assertSame('MZXW6YTB', Base32::encode('fooba'));
        self::assertSame('MZXW6YTBOI', Base32::encode('foobar'));
    }

    public function testDecodesKnownRfc4648VectorsWithoutPadding(): void
    {
        self::assertSame('', Base32::decode(''));
        self::assertSame('f', Base32::decode('MY'));
        self::assertSame('fo', Base32::decode('MZXQ'));
        self::assertSame('foo', Base32::decode('MZXW6'));
        self::assertSame('foob', Base32::decode('MZXW6YQ'));
        self::assertSame('fooba', Base32::decode('MZXW6YTB'));
        self::assertSame('foobar', Base32::decode('MZXW6YTBOI'));
    }

    public function testDecodesLowercaseWhitespaceAndPadding(): void
    {
        self::assertSame('foobar', Base32::decode("mzxw 6ytb\noi======"));
    }

    public function testRoundTripsBinaryData(): void
    {
        $bytes = "\x00\x01\x02\xFE\xFFsecret";

        self::assertSame($bytes, Base32::decode(Base32::encode($bytes)));
    }

    public function testRejectsInvalidCharacters(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid Base32 character "8".');

        Base32::decode('ABC8');
    }
}
