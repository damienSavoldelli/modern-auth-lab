<?php

declare(strict_types=1);

namespace ModernAuthLab\Security\Totp;

use InvalidArgumentException;

/**
 * Runtime configuration for TOTP challenge rate limiting.
 *
 * The values come from environment configuration so local, CI, and production
 * deployments can tune MFA brute-force protection without changing code.
 */
final readonly class TotpRateLimitConfig
{
    public const ENV_MAX_ATTEMPTS = 'TOTP_RATE_LIMIT_MAX_ATTEMPTS';
    public const ENV_LOCK_SECONDS = 'TOTP_RATE_LIMIT_LOCK_SECONDS';

    /**
     * @param int $maxAttempts Maximum failed TOTP submissions before blocking.
     * @param int $lockSeconds Temporary lock duration in seconds.
     */
    private function __construct(
        public int $maxAttempts,
        public int $lockSeconds,
    ) {}

    /**
     * Build TOTP rate-limit configuration from environment variables.
     *
     * @param array<string, string|false> $environment Environment-like key/value map.
     *
     * @return self Validated TOTP rate-limit configuration.
     *
     * @throws InvalidArgumentException When a value is missing or invalid.
     */
    public static function fromEnvironment(array $environment): self
    {
        return new self(
            self::positiveIntegerFromEnvironment($environment, self::ENV_MAX_ATTEMPTS),
            self::positiveIntegerFromEnvironment($environment, self::ENV_LOCK_SECONDS),
        );
    }

    /**
     * Read a strictly positive integer from the environment.
     *
     * @param array<string, string|false> $environment Environment-like key/value map.
     * @param string $name Environment variable name.
     *
     * @return int Positive integer value.
     *
     * @throws InvalidArgumentException When the variable is missing or invalid.
     */
    private static function positiveIntegerFromEnvironment(array $environment, string $name): int
    {
        $value = $environment[$name] ?? false;
        if (! is_string($value) || trim($value) === '') {
            throw new InvalidArgumentException(sprintf('Environment variable "%s" must contain a positive integer.', $name));
        }

        $trimmedValue = trim($value);
        if (! ctype_digit($trimmedValue)) {
            throw new InvalidArgumentException(sprintf('Environment variable "%s" must contain a positive integer.', $name));
        }

        $integerValue = (int) $trimmedValue;
        if ($integerValue < 1) {
            throw new InvalidArgumentException(sprintf('Environment variable "%s" must be greater than zero.', $name));
        }

        return $integerValue;
    }
}
