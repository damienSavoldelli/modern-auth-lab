<?php

declare(strict_types=1);

namespace ModernAuthLab\Tests\Security\WebAuthn;

use ModernAuthLab\Security\WebAuthn\WebAuthnConfig;
use PHPUnit\Framework\TestCase;

final class WebAuthnConfigTest extends TestCase
{
    public function testBuildsDefaultLocalDevelopmentConfig(): void
    {
        $config = WebAuthnConfig::fromEnvironment([]);

        self::assertSame('127.0.0.1', $config->rpId);
        self::assertSame('Modern Auth Lab', $config->rpName);
        self::assertSame(['http://127.0.0.1:8080'], $config->allowedOrigins);
        self::assertSame(300, $config->challengeTtlSeconds);
        self::assertSame(60_000, $config->timeoutMs);
        self::assertSame('preferred', $config->userVerification);
    }

    public function testBuildsConfigFromEnvironment(): void
    {
        $config = WebAuthnConfig::fromEnvironment([
            WebAuthnConfig::ENV_RP_ID => 'auth.example.com',
            WebAuthnConfig::ENV_RP_NAME => 'Example Auth',
            WebAuthnConfig::ENV_ALLOWED_ORIGINS => 'https://auth.example.com,https://login.example.com',
            WebAuthnConfig::ENV_CHALLENGE_TTL_SECONDS => '120',
            WebAuthnConfig::ENV_TIMEOUT_MS => '45000',
            WebAuthnConfig::ENV_USER_VERIFICATION => 'required',
        ]);

        self::assertSame('auth.example.com', $config->rpId);
        self::assertSame('Example Auth', $config->rpName);
        self::assertSame(['https://auth.example.com', 'https://login.example.com'], $config->allowedOrigins);
        self::assertSame(120, $config->challengeTtlSeconds);
        self::assertSame(45_000, $config->timeoutMs);
        self::assertSame('required', $config->userVerification);
    }

    public function testRejectsOriginWithoutScheme(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new WebAuthnConfig('example.com', 'Example', ['example.com'], 300, 60_000, 'preferred');
    }

    public function testRejectsInvalidUserVerificationPolicy(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new WebAuthnConfig('example.com', 'Example', ['https://example.com'], 300, 60_000, 'always');
    }
}
