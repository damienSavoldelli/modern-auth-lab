<?php

declare(strict_types=1);

namespace ModernAuthLab\Tests\Security\Totp;

use InvalidArgumentException;
use ModernAuthLab\Security\Totp\Base32;
use ModernAuthLab\Security\Totp\TotpProvisioningUri;
use ModernAuthLab\Security\Totp\TotpSecret;
use PHPUnit\Framework\TestCase;

final class TotpProvisioningUriTest extends TestCase
{
    public function testBuildsDefaultProvisioningUri(): void
    {
        $secret = TotpSecret::fromBase32(Base32::encode('12345678901234567890'));
        $uri = new TotpProvisioningUri('Modern Auth Lab', 'dev@example.com', $secret);

        self::assertSame(
            'otpauth://totp/Modern%20Auth%20Lab:dev%40example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Modern%20Auth%20Lab&algorithm=SHA1&digits=6&period=30',
            $uri->uri(),
        );
    }

    public function testBuildsConfigurableProvisioningUri(): void
    {
        $secret = TotpSecret::fromBase32(Base32::encode('12345678901234567890'));
        $uri = new TotpProvisioningUri(
            'Modern/Auth Lab',
            'admin+totp@example.com',
            $secret,
            'SHA512',
            8,
            60,
        );

        self::assertSame(
            'otpauth://totp/Modern%2FAuth%20Lab:admin%2Btotp%40example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Modern%2FAuth%20Lab&algorithm=SHA512&digits=8&period=60',
            $uri->uri(),
        );
    }

    public function testRejectsEmptyIssuer(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('TOTP issuer cannot be empty.');

        new TotpProvisioningUri(' ', 'dev@example.com', TotpSecret::generate());
    }

    public function testRejectsEmptyAccountLabel(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('TOTP account label cannot be empty.');

        new TotpProvisioningUri('Modern Auth Lab', '', TotpSecret::generate());
    }

    public function testRejectsUnsupportedAlgorithm(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('TOTP algorithm must be SHA1, SHA256, or SHA512.');

        new TotpProvisioningUri('Modern Auth Lab', 'dev@example.com', TotpSecret::generate(), 'MD5');
    }

    public function testRejectsUnsupportedDigits(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('TOTP digits must be 6 or 8.');

        new TotpProvisioningUri('Modern Auth Lab', 'dev@example.com', TotpSecret::generate(), digits: 7);
    }

    public function testRejectsInvalidPeriod(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('TOTP period must be at least 1 second.');

        new TotpProvisioningUri('Modern Auth Lab', 'dev@example.com', TotpSecret::generate(), period: 0);
    }
}
