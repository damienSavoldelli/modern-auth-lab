<?php

declare(strict_types=1);

namespace ModernAuthLab\Tests\Security\Totp;

use ModernAuthLab\Security\Totp\TotpChallengeRateLimiter;
use ModernAuthLab\Security\Totp\TotpRateLimitConfig;
use PHPUnit\Framework\TestCase;

final class TotpChallengeRateLimiterTest extends TestCase
{
    public function testAllowsAttemptsBeforeLimitIsReached(): void
    {
        $storage = [];
        $now = 1000;
        $limiter = new TotpChallengeRateLimiter(
            $storage,
            $this->config(maxAttempts: 3, lockSeconds: 300),
            static fn(): int => $now,
        );

        $limiter->recordFailure('totp-key');
        $limiter->recordFailure('totp-key');

        self::assertTrue($limiter->isAllowed('totp-key'));
    }

    public function testBlocksAfterLimitIsReached(): void
    {
        $storage = [];
        $now = 1000;
        $limiter = new TotpChallengeRateLimiter(
            $storage,
            $this->config(maxAttempts: 3, lockSeconds: 300),
            static fn(): int => $now,
        );

        $limiter->recordFailure('totp-key');
        $limiter->recordFailure('totp-key');
        $limiter->recordFailure('totp-key');

        self::assertFalse($limiter->isAllowed('totp-key'));
    }

    public function testAllowsAgainAfterLockExpires(): void
    {
        $storage = [];
        $now = 1000;
        $limiter = new TotpChallengeRateLimiter(
            $storage,
            $this->config(maxAttempts: 3, lockSeconds: 300),
            static function () use (&$now): int {
                return $now;
            },
        );

        $limiter->recordFailure('totp-key');
        $limiter->recordFailure('totp-key');
        $limiter->recordFailure('totp-key');

        $now = 1299;

        self::assertFalse($limiter->isAllowed('totp-key'));

        $now = 1301;

        self::assertTrue($limiter->isAllowed('totp-key'));
    }

    public function testClearRemovesAttemptsAfterSuccessfulChallenge(): void
    {
        $storage = [];
        $now = 1000;
        $limiter = new TotpChallengeRateLimiter(
            $storage,
            $this->config(maxAttempts: 1, lockSeconds: 300),
            static fn(): int => $now,
        );

        $limiter->recordFailure('totp-key');
        $limiter->clear('totp-key');

        self::assertTrue($limiter->isAllowed('totp-key'));
    }

    public function testIgnoresAttemptsOutsideConfiguredWindow(): void
    {
        $storage = [];
        $now = 1000;
        $limiter = new TotpChallengeRateLimiter(
            $storage,
            $this->config(maxAttempts: 2, lockSeconds: 300),
            static function () use (&$now): int {
                return $now;
            },
        );

        $limiter->recordFailure('totp-key');

        $now = 1301;

        $limiter->recordFailure('totp-key');

        self::assertTrue($limiter->isAllowed('totp-key'));
    }

    private function config(int $maxAttempts, int $lockSeconds): TotpRateLimitConfig
    {
        return TotpRateLimitConfig::fromEnvironment([
            'TOTP_RATE_LIMIT_MAX_ATTEMPTS' => (string) $maxAttempts,
            'TOTP_RATE_LIMIT_LOCK_SECONDS' => (string) $lockSeconds,
        ]);
    }
}
