<?php

declare(strict_types=1);

namespace ModernAuthLab\Security\WebAuthn;

use InvalidArgumentException;

/**
 * Server-side WebAuthn relying-party configuration.
 *
 * These values define which site is allowed to create and verify Passkeys for
 * this application. They must be controlled by deployment configuration, not by
 * browser input.
 */
final readonly class WebAuthnConfig
{
    public const ENV_RP_ID = 'WEBAUTHN_RP_ID';
    public const ENV_RP_NAME = 'WEBAUTHN_RP_NAME';
    public const ENV_ALLOWED_ORIGINS = 'WEBAUTHN_ALLOWED_ORIGINS';
    public const ENV_CHALLENGE_TTL_SECONDS = 'WEBAUTHN_CHALLENGE_TTL_SECONDS';
    public const ENV_TIMEOUT_MS = 'WEBAUTHN_TIMEOUT_MS';
    public const ENV_USER_VERIFICATION = 'WEBAUTHN_USER_VERIFICATION';

    private const DEFAULT_RP_ID = '127.0.0.1';
    private const DEFAULT_RP_NAME = 'Modern Auth Lab';
    private const DEFAULT_ALLOWED_ORIGINS = 'http://127.0.0.1:8080';
    private const DEFAULT_CHALLENGE_TTL_SECONDS = 300;
    private const DEFAULT_TIMEOUT_MS = 60_000;
    private const DEFAULT_USER_VERIFICATION = 'preferred';

    /**
     * @param string $rpId Relying-party identifier, usually the effective domain.
     * @param string $rpName User-facing relying-party name.
     * @param list<string> $allowedOrigins Origins accepted during server-side verification.
     * @param int $challengeTtlSeconds Challenge lifetime in seconds.
     * @param int $timeoutMs Browser ceremony timeout hint in milliseconds.
     * @param string $userVerification User verification policy: required, preferred, or discouraged.
     */
    public function __construct(
        public string $rpId,
        public string $rpName,
        public array $allowedOrigins,
        public int $challengeTtlSeconds,
        public int $timeoutMs,
        public string $userVerification,
    ) {
        if ($this->rpId === '') {
            throw new InvalidArgumentException('WebAuthn RP ID cannot be empty.');
        }

        if ($this->rpName === '') {
            throw new InvalidArgumentException('WebAuthn RP name cannot be empty.');
        }

        if ($this->allowedOrigins === []) {
            throw new InvalidArgumentException('WebAuthn allowed origins cannot be empty.');
        }

        foreach ($this->allowedOrigins as $origin) {
            if (! str_starts_with($origin, 'http://') && ! str_starts_with($origin, 'https://')) {
                throw new InvalidArgumentException('WebAuthn allowed origins must include a scheme.');
            }
        }

        if ($this->challengeTtlSeconds <= 0) {
            throw new InvalidArgumentException('WebAuthn challenge TTL must be greater than zero.');
        }

        if ($this->timeoutMs <= 0) {
            throw new InvalidArgumentException('WebAuthn timeout must be greater than zero.');
        }

        if (! in_array($this->userVerification, ['required', 'preferred', 'discouraged'], true)) {
            throw new InvalidArgumentException('WebAuthn user verification must be required, preferred, or discouraged.');
        }
    }

    /**
     * Build WebAuthn configuration from environment variables.
     *
     * @param array<string, string|false> $environment Environment-like key/value map.
     *
     * @return self Validated WebAuthn configuration.
     */
    public static function fromEnvironment(array $environment): self
    {
        return new self(
            self::stringValue($environment, self::ENV_RP_ID, self::DEFAULT_RP_ID),
            self::stringValue($environment, self::ENV_RP_NAME, self::DEFAULT_RP_NAME),
            self::originListValue($environment, self::ENV_ALLOWED_ORIGINS, self::DEFAULT_ALLOWED_ORIGINS),
            self::positiveIntValue($environment, self::ENV_CHALLENGE_TTL_SECONDS, self::DEFAULT_CHALLENGE_TTL_SECONDS),
            self::positiveIntValue($environment, self::ENV_TIMEOUT_MS, self::DEFAULT_TIMEOUT_MS),
            self::stringValue($environment, self::ENV_USER_VERIFICATION, self::DEFAULT_USER_VERIFICATION),
        );
    }

    /**
     * @param array<string, string|false> $environment
     */
    private static function stringValue(array $environment, string $key, string $default): string
    {
        $value = $environment[$key] ?? false;

        if (! is_string($value) || trim($value) === '') {
            return $default;
        }

        return trim($value);
    }

    /**
     * @param array<string, string|false> $environment
     *
     * @return list<string>
     */
    private static function originListValue(array $environment, string $key, string $default): array
    {
        $value = self::stringValue($environment, $key, $default);
        $origins = array_values(array_filter(array_map(trim(...), explode(',', $value))));

        if ($origins === []) {
            throw new InvalidArgumentException('WebAuthn allowed origins cannot be empty.');
        }

        return $origins;
    }

    /**
     * @param array<string, string|false> $environment
     */
    private static function positiveIntValue(array $environment, string $key, int $default): int
    {
        $value = $environment[$key] ?? false;

        if (! is_string($value) || trim($value) === '') {
            return $default;
        }

        if (preg_match('/^[1-9][0-9]*$/', trim($value)) !== 1) {
            throw new InvalidArgumentException(sprintf('Environment variable "%s" must be a positive integer.', $key));
        }

        return (int) trim($value);
    }
}
