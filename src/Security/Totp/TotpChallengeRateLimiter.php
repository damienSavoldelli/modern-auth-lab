<?php

declare(strict_types=1);

namespace ModernAuthLab\Security\Totp;

use Closure;

/**
 * Session-backed rate limiter for TOTP challenge failures.
 *
 * The limiter stores timestamps and lock metadata only. The caller owns the
 * identifier shape, which allows the HTTP layer to combine user id and client
 * IP without this class knowing about request semantics.
 */
final class TotpChallengeRateLimiter
{
    private const STORAGE_KEY = '_totp_challenge_rate_limits';

    /**
     * @param array<string, mixed> $storage Session-backed limiter storage.
     * @param TotpRateLimitConfig $config Runtime TOTP rate-limit policy.
     * @param Closure(): int|null $now Optional clock for deterministic tests.
     */
    public function __construct(
        private array &$storage,
        private TotpRateLimitConfig $config,
        private ?Closure $now = null,
    ) {}

    /**
     * Check whether the identifier can submit another TOTP challenge attempt.
     *
     * @param string $identifier Opaque TOTP challenge rate-limit key.
     *
     * @return bool True when another attempt is currently allowed.
     */
    public function isAllowed(string $identifier): bool
    {
        $record = $this->record($identifier);

        return ($record['locked_until'] ?? 0) <= $this->now();
    }

    /**
     * Record one failed TOTP challenge attempt and lock when the threshold is reached.
     *
     * @param string $identifier Opaque TOTP challenge rate-limit key.
     *
     * @return void
     */
    public function recordFailure(string $identifier): void
    {
        $now = $this->now();
        $record = $this->record($identifier);
        $attempts = $this->recentAttempts($record, $now);
        $attempts[] = $now;

        $this->storage[self::STORAGE_KEY][$identifier] = [
            'attempts' => $attempts,
            'locked_until' => count($attempts) >= $this->config->maxAttempts ? $now + $this->config->lockSeconds : 0,
        ];
    }

    /**
     * Remove limiter state after successful TOTP completion.
     *
     * @param string $identifier Opaque TOTP challenge rate-limit key.
     *
     * @return void
     */
    public function clear(string $identifier): void
    {
        unset($this->storage[self::STORAGE_KEY][$identifier]);
    }

    /**
     * @param string $identifier Opaque TOTP challenge rate-limit key.
     *
     * @return array{attempts: list<int>, locked_until: int} Normalized limiter record.
     */
    private function record(string $identifier): array
    {
        $records = $this->storage[self::STORAGE_KEY] ?? [];

        if (! is_array($records)) {
            return ['attempts' => [], 'locked_until' => 0];
        }

        $record = $records[$identifier] ?? [];

        if (! is_array($record)) {
            return ['attempts' => [], 'locked_until' => 0];
        }

        $attempts = $record['attempts'] ?? [];
        $lockedUntil = $record['locked_until'] ?? 0;

        return [
            'attempts' => is_array($attempts) ? array_values(array_filter($attempts, 'is_int')) : [],
            'locked_until' => is_int($lockedUntil) ? $lockedUntil : 0,
        ];
    }

    /**
     * @param array{attempts: list<int>, locked_until: int} $record Normalized limiter record.
     * @param int $now Current unix timestamp.
     *
     * @return list<int> Attempt timestamps still inside the configured lock window.
     */
    private function recentAttempts(array $record, int $now): array
    {
        $minimumTimestamp = $now - $this->config->lockSeconds;

        return array_values(array_filter(
            $record['attempts'],
            static fn(int $attempt): bool => $attempt >= $minimumTimestamp,
        ));
    }

    private function now(): int
    {
        if ($this->now !== null) {
            return ($this->now)();
        }

        return time();
    }
}
