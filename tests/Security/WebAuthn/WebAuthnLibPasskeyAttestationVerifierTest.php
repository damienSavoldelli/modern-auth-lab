<?php

declare(strict_types=1);

namespace ModernAuthLab\Tests\Security\WebAuthn;

use ModernAuthLab\Domain\User\User;
use ModernAuthLab\Security\WebAuthn\WebAuthnConfig;
use ModernAuthLab\Security\WebAuthn\WebAuthnLibPasskeyAttestationVerifier;
use PHPUnit\Framework\TestCase;

final class WebAuthnLibPasskeyAttestationVerifierTest extends TestCase
{
    public function testRejectsInvalidBrowserCredentialPayload(): void
    {
        $verifier = new WebAuthnLibPasskeyAttestationVerifier(
            new WebAuthnConfig('127.0.0.1', 'Modern Auth Lab', ['http://127.0.0.1:8080'], 300, 60_000, 'preferred'),
        );

        $this->expectException(\Throwable::class);

        $verifier->verify(
            new User(1, 'user@example.com', 'hash', '2026-01-01 00:00:00', '2026-01-01 00:00:00'),
            'challenge',
            ['type' => 'public-key'],
        );
    }
}
