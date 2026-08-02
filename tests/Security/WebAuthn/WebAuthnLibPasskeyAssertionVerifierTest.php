<?php

declare(strict_types=1);

namespace ModernAuthLab\Tests\Security\WebAuthn;

use ModernAuthLab\Infrastructure\Persistence\UserPasskeyCredential;
use ModernAuthLab\Security\WebAuthn\WebAuthnConfig;
use ModernAuthLab\Security\WebAuthn\WebAuthnLibPasskeyAssertionVerifier;
use PHPUnit\Framework\TestCase;

final class WebAuthnLibPasskeyAssertionVerifierTest extends TestCase
{
    public function testRejectsInvalidBrowserAssertionPayload(): void
    {
        $verifier = new WebAuthnLibPasskeyAssertionVerifier(
            new WebAuthnConfig('127.0.0.1', 'Modern Auth Lab', ['http://127.0.0.1:8080'], 300, 60_000, 'preferred'),
        );

        $this->expectException(\Throwable::class);

        $verifier->verify(
            new UserPasskeyCredential(
                1,
                1,
                'Y3JlZGVudGlhbC1pZA',
                'cHVibGljLWtleQ',
                0,
                'Work laptop',
                ['internal'],
                'none',
                '00000000-0000-0000-0000-000000000000',
                'active',
                null,
                null,
                '2026-01-01 00:00:00',
                '2026-01-01 00:00:00',
            ),
            'challenge',
            ['type' => 'public-key'],
        );
    }
}
