<?php

declare(strict_types=1);

namespace ModernAuthLab\Security\Totp;

use InvalidArgumentException;
use SensitiveParameter;

/**
 * Configuration for server-side TOTP secret encryption.
 *
 * The key protects user TOTP secrets before they are persisted. It must come
 * from trusted runtime configuration and must never be stored in SQLite.
 */
final readonly class TotpSecretEncryptionConfig
{
    public const DEFAULT_KEY_ID = 'local';
    public const ENV_KEY = 'TOTP_SECRET_ENCRYPTION_KEY';
    private const KEY_BYTES = SODIUM_CRYPTO_SECRETBOX_KEYBYTES;

    /**
     * @param string $key Raw 32-byte encryption key.
     * @param string $keyId Stable identifier for this encryption key.
     */
    private function __construct(
        #[SensitiveParameter]
        public string $key,
        public string $keyId,
    ) {}

    /**
     * Build encryption configuration from an environment variable.
     *
     * @param array<string, string|false> $environment Environment-like key/value map.
     * @param string $keyName Environment variable containing a Base64-encoded key.
     * @param string $keyId Stable key identifier stored with protected secrets.
     *
     * @return self Validated encryption configuration.
     *
     * @throws InvalidArgumentException When the environment value is missing or invalid.
     */
    public static function fromEnvironment(
        array $environment,
        string $keyName = self::ENV_KEY,
        string $keyId = self::DEFAULT_KEY_ID,
    ): self {
        if ($keyId === '') {
            throw new InvalidArgumentException('TOTP secret encryption key id cannot be empty.');
        }

        $encodedKey = $environment[$keyName] ?? false;
        if (! is_string($encodedKey) || trim($encodedKey) === '') {
            throw new InvalidArgumentException(sprintf('Environment variable "%s" must contain a Base64 TOTP encryption key.', $keyName));
        }

        $key = base64_decode(trim($encodedKey), true);
        if ($key === false || strlen($key) !== self::KEY_BYTES) {
            throw new InvalidArgumentException(sprintf('Environment variable "%s" must decode to exactly 32 bytes.', $keyName));
        }

        return new self($key, $keyId);
    }

    /**
     * Create the secret protector configured with this server key.
     *
     * @return TotpSecretProtector Configured TOTP secret protector.
     */
    public function protector(): TotpSecretProtector
    {
        return new TotpSecretProtector($this->key, $this->keyId);
    }
}
