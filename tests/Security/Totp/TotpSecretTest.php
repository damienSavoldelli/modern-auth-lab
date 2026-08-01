<?php

declare(strict_types=1);

namespace ModernAuthLab\Tests\Security\Totp;

use InvalidArgumentException;
use ModernAuthLab\Security\Totp\Base32;
use ModernAuthLab\Security\Totp\TotpSecret;
use PHPUnit\Framework\TestCase;

final class TotpSecretTest extends TestCase
{
    public function testGeneratesDefaultTwentyByteSecret(): void
    {
        $secret = TotpSecret::generate();

        self::assertSame(20, strlen($secret->bytes()));
        self::assertMatchesRegularExpression('/^[A-Z2-7]+$/', $secret->base32());
        self::assertSame($secret->bytes(), Base32::decode($secret->base32()));
    }

    public function testGeneratesCustomLengthSecret(): void
    {
        $secret = TotpSecret::generate(32);

        self::assertSame(32, strlen($secret->bytes()));
        self::assertSame($secret->bytes(), Base32::decode($secret->base32()));
    }

    public function testRecreatesSecretFromBase32(): void
    {
        $bytes = '12345678901234567890';
        $base32 = Base32::encode($bytes);

        $secret = TotpSecret::fromBase32($base32);

        self::assertSame($base32, $secret->base32());
        self::assertSame($bytes, $secret->bytes());
    }

    public function testNormalizesBase32Input(): void
    {
        $secret = TotpSecret::fromBase32('gezd gnbv gy3t qojq gezdgnbvgy3tqojq======');

        self::assertSame('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', $secret->base32());
        self::assertSame('12345678901234567890', $secret->bytes());
    }

    public function testRejectsGeneratedSecretsBelowMinimumLength(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('TOTP secret length must be at least 16 bytes.');

        TotpSecret::generate(15);
    }

    public function testRejectsImportedSecretsBelowMinimumLength(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('TOTP secret must contain at least 16 bytes.');

        TotpSecret::fromBase32(Base32::encode('too-short'));
    }

    public function testRejectsInvalidBase32Input(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid Base32 character "8".');

        TotpSecret::fromBase32('ABC8');
    }
}
