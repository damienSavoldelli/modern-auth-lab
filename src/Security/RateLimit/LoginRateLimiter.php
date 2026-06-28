<?php

declare(strict_types=1);

namespace ModernAuthLab\Security\RateLimit;

use Closure;

/**
 * First-stage login throttling.
 *
 * It is intentionally session-backed so the project can introduce brute-force
 * controls before adding shared security state or a distributed rate-limiting
 * store.
 */
final class LoginRateLimiter
{
    private const STORAGE_KEY = '_login_rate_limits';

    /**
     * @param array<string, mixed> $storage
     * @param Closure(): int|null $now
     */
    public function __construct(
        private array &$storage,
        private int $maxAttempts = 5,
        private int $windowSeconds = 900,
        private int $lockSeconds = 300,
        private ?Closure $now = null,
    ) {}

    /**
     * Check whether the identifier can attempt password authentication.
     */
    public function isAllowed(string $identifier): bool
    {
        $record = $this->record($identifier);
        $now = $this->now();

        // A lock wins over the rolling window. This keeps the response stable
        // until the temporary lock expires.
        if (($record['locked_until'] ?? 0) > $now) {
            return false;
        }

        return count($this->recentAttempts($record, $now)) < $this->maxAttempts;
    }

    /**
     * Record one failed attempt and lock the identifier if the threshold is met.
     */
    public function recordFailure(string $identifier): void
    {
        $now = $this->now();
        $record = $this->record($identifier);
        $attempts = $this->recentAttempts($record, $now);
        $attempts[] = $now;

        // Store timestamps, not request data. The controller owns the identifier
        // shape so this class does not need to know about email or IP semantics.
        $this->storage[self::STORAGE_KEY][$identifier] = [
            'attempts' => $attempts,
            'locked_until' => count($attempts) >= $this->maxAttempts ? $now + $this->lockSeconds : 0,
        ];
    }

    /**
     * Remove limiter state after successful authentication.
     */
    public function clear(string $identifier): void
    {
        unset($this->storage[self::STORAGE_KEY][$identifier]);
    }

    /**
     * @return array{attempts: list<int>, locked_until: int}
     */
    private function record(string $identifier): array
    {
        $records = $this->storage[self::STORAGE_KEY] ?? [];

        // Session data is user-controlled storage from PHP's point of view, so
        // read defensively and fall back to an empty limiter state.
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
     * @param array{attempts: list<int>, locked_until: int} $record
     *
     * @return list<int>
     */
    private function recentAttempts(array $record, int $now): array
    {
        $minimumTimestamp = $now - $this->windowSeconds;

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
