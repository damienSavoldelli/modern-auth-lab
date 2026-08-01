<?php

declare(strict_types=1);

namespace ModernAuthLab\Tests\Security\Totp;

use InvalidArgumentException;
use ModernAuthLab\Security\Totp\TotpRateLimitConfig;
use PHPUnit\Framework\TestCase;

final class TotpRateLimitConfigTest extends TestCase
{
    public function testBuildsConfigFromEnvironment(): void
    {
        $config = TotpRateLimitConfig::fromEnvironment([
            'TOTP_RATE_LIMIT_MAX_ATTEMPTS' => '5',
            'TOTP_RATE_LIMIT_LOCK_SECONDS' => '300',
        ]);

        self::assertSame(5, $config->maxAttempts);
        self::assertSame(300, $config->lockSeconds);
    }

    public function testTrimsEnvironmentValues(): void
    {
        $config = TotpRateLimitConfig::fromEnvironment([
            'TOTP_RATE_LIMIT_MAX_ATTEMPTS' => ' 5 ',
            'TOTP_RATE_LIMIT_LOCK_SECONDS' => ' 300 ',
        ]);

        self::assertSame(5, $config->maxAttempts);
        self::assertSame(300, $config->lockSeconds);
    }

    public function testRejectsMissingMaxAttempts(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Environment variable "TOTP_RATE_LIMIT_MAX_ATTEMPTS" must contain a positive integer.');

        TotpRateLimitConfig::fromEnvironment([
            'TOTP_RATE_LIMIT_LOCK_SECONDS' => '300',
        ]);
    }

    public function testRejectsNonIntegerLockSeconds(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Environment variable "TOTP_RATE_LIMIT_LOCK_SECONDS" must contain a positive integer.');

        TotpRateLimitConfig::fromEnvironment([
            'TOTP_RATE_LIMIT_MAX_ATTEMPTS' => '5',
            'TOTP_RATE_LIMIT_LOCK_SECONDS' => 'five minutes',
        ]);
    }

    public function testRejectsZeroValues(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Environment variable "TOTP_RATE_LIMIT_MAX_ATTEMPTS" must be greater than zero.');

        TotpRateLimitConfig::fromEnvironment([
            'TOTP_RATE_LIMIT_MAX_ATTEMPTS' => '0',
            'TOTP_RATE_LIMIT_LOCK_SECONDS' => '300',
        ]);
    }
}
