<?php

declare(strict_types=1);

namespace ModernAuthLab\Tests\Security\Totp;

use InvalidArgumentException;
use ModernAuthLab\Security\Totp\Base32;
use ModernAuthLab\Security\Totp\TotpGenerator;
use ModernAuthLab\Security\Totp\TotpSecret;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class TotpGeneratorTest extends TestCase
{
    /**
     * @param non-empty-string $algorithm
     */
    #[DataProvider('rfc6238Vectors')]
    public function testGeneratesKnownRfc6238Vectors(
        string $algorithm,
        string $secretBytes,
        int $timestamp,
        string $expectedCode,
    ): void {
        $secret = TotpSecret::fromBase32(Base32::encode($secretBytes));
        $generator = new TotpGenerator($algorithm, digits: 8);

        self::assertSame($expectedCode, $generator->generate($secret, $timestamp));
    }

    public function testGeneratesDefaultSixDigitCode(): void
    {
        $secret = TotpSecret::fromBase32(Base32::encode('12345678901234567890'));
        $generator = new TotpGenerator();

        self::assertSame('287082', $generator->generate($secret, 59));
    }

    public function testUsesConfiguredPeriod(): void
    {
        $secret = TotpSecret::fromBase32(Base32::encode('12345678901234567890'));
        $generator = new TotpGenerator(period: 60);

        self::assertSame($generator->generate($secret, 60), $generator->generate($secret, 119));
    }

    public function testRejectsUnsupportedAlgorithm(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('TOTP algorithm must be SHA1, SHA256, or SHA512.');

        new TotpGenerator('MD5');
    }

    public function testRejectsUnsupportedDigits(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('TOTP digits must be 6 or 8.');

        new TotpGenerator(digits: 7);
    }

    public function testRejectsInvalidPeriod(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('TOTP period must be at least 1 second.');

        new TotpGenerator(period: 0);
    }

    public function testRejectsNegativeTimestamp(): void
    {
        $secret = TotpSecret::fromBase32(Base32::encode('12345678901234567890'));
        $generator = new TotpGenerator();

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('TOTP timestamp cannot be negative.');

        $generator->generate($secret, -1);
    }

    /**
     * @return list<array{algorithm: non-empty-string, secretBytes: string, timestamp: int, expectedCode: string}>
     */
    public static function rfc6238Vectors(): array
    {
        return [
            [
                'algorithm' => 'SHA1',
                'secretBytes' => '12345678901234567890',
                'timestamp' => 59,
                'expectedCode' => '94287082',
            ],
            [
                'algorithm' => 'SHA256',
                'secretBytes' => '12345678901234567890123456789012',
                'timestamp' => 59,
                'expectedCode' => '46119246',
            ],
            [
                'algorithm' => 'SHA512',
                'secretBytes' => '1234567890123456789012345678901234567890123456789012345678901234',
                'timestamp' => 59,
                'expectedCode' => '90693936',
            ],
            [
                'algorithm' => 'SHA1',
                'secretBytes' => '12345678901234567890',
                'timestamp' => 1111111109,
                'expectedCode' => '07081804',
            ],
            [
                'algorithm' => 'SHA1',
                'secretBytes' => '12345678901234567890',
                'timestamp' => 20000000000,
                'expectedCode' => '65353130',
            ],
        ];
    }
}
