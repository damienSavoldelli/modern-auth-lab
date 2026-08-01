<?php

declare(strict_types=1);

namespace ModernAuthLab\Tests\Security\Totp;

use InvalidArgumentException;
use ModernAuthLab\Security\Totp\TotpSecret;
use ModernAuthLab\Security\Totp\TotpSecretEncryptionConfig;
use PHPUnit\Framework\TestCase;

final class TotpSecretEncryptionConfigTest extends TestCase
{
    public function testLoadsBase64KeyFromEnvironment(): void
    {
        $key = str_repeat('a', 32);

        $config = TotpSecretEncryptionConfig::fromEnvironment([
            TotpSecretEncryptionConfig::ENV_KEY => base64_encode($key),
        ]);

        self::assertSame($key, $config->key);
        self::assertSame('local', $config->keyId);
    }

    public function testBuildsProtectorFromConfig(): void
    {
        $secret = TotpSecret::fromBase32('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
        $config = TotpSecretEncryptionConfig::fromEnvironment([
            TotpSecretEncryptionConfig::ENV_KEY => base64_encode(str_repeat('a', 32)),
        ], keyId: 'primary');

        $protector = $config->protector();
        $protected = $protector->protect($secret);

        self::assertSame('primary', $protected->keyId);
        self::assertSame($secret->base32(), $protector->reveal($protected)->base32());
    }

    public function testRejectsMissingEnvironmentKey(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Environment variable "TOTP_SECRET_ENCRYPTION_KEY" must contain a Base64 TOTP encryption key.');

        TotpSecretEncryptionConfig::fromEnvironment([]);
    }

    public function testRejectsInvalidBase64EnvironmentKey(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Environment variable "TOTP_SECRET_ENCRYPTION_KEY" must decode to exactly 32 bytes.');

        TotpSecretEncryptionConfig::fromEnvironment([
            TotpSecretEncryptionConfig::ENV_KEY => 'not-base64',
        ]);
    }

    public function testRejectsWrongDecodedKeyLength(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Environment variable "TOTP_SECRET_ENCRYPTION_KEY" must decode to exactly 32 bytes.');

        TotpSecretEncryptionConfig::fromEnvironment([
            TotpSecretEncryptionConfig::ENV_KEY => base64_encode('too-short'),
        ]);
    }

    public function testRejectsEmptyKeyId(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('TOTP secret encryption key id cannot be empty.');

        TotpSecretEncryptionConfig::fromEnvironment([
            TotpSecretEncryptionConfig::ENV_KEY => base64_encode(str_repeat('a', 32)),
        ], keyId: '');
    }
}
