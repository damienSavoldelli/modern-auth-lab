<?php

declare(strict_types=1);

namespace ModernAuthLab\Tests\Security\RateLimit;

use ModernAuthLab\Security\RateLimit\LoginRateLimiter;
use PHPUnit\Framework\TestCase;

final class LoginRateLimiterTest extends TestCase
{
    public function testAllowsAttemptsBeforeLimitIsReached(): void
    {
        $storage = [];
        $now = 1000;
        $limiter = new LoginRateLimiter($storage, maxAttempts: 3, now: static fn(): int => $now);

        $limiter->recordFailure('login-key');
        $limiter->recordFailure('login-key');

        self::assertTrue($limiter->isAllowed('login-key'));
    }

    public function testBlocksAfterLimitIsReached(): void
    {
        $storage = [];
        $now = 1000;
        $limiter = new LoginRateLimiter($storage, maxAttempts: 3, now: static fn(): int => $now);

        $limiter->recordFailure('login-key');
        $limiter->recordFailure('login-key');
        $limiter->recordFailure('login-key');

        self::assertFalse($limiter->isAllowed('login-key'));
    }

    public function testAllowsAgainAfterLockExpires(): void
    {
        $storage = [];
        $now = 1000;
        $limiter = new LoginRateLimiter(
            $storage,
            maxAttempts: 3,
            windowSeconds: 900,
            lockSeconds: 300,
            now: static function () use (&$now): int {
                return $now;
            },
        );

        $limiter->recordFailure('login-key');
        $limiter->recordFailure('login-key');
        $limiter->recordFailure('login-key');

        $now = 1301;

        self::assertFalse($limiter->isAllowed('login-key'));

        $now = 1901;

        self::assertTrue($limiter->isAllowed('login-key'));
    }

    public function testClearRemovesAttempts(): void
    {
        $storage = [];
        $now = 1000;
        $limiter = new LoginRateLimiter($storage, maxAttempts: 1, now: static fn(): int => $now);

        $limiter->recordFailure('login-key');
        $limiter->clear('login-key');

        self::assertTrue($limiter->isAllowed('login-key'));
    }
}
