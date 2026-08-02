<?php

declare(strict_types=1);

namespace ModernAuthLab\Tests\Platform;

use PHPUnit\Framework\TestCase;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialRequestOptions;

/**
 * Guards the WebAuthn dependency boundary expected by the project.
 *
 * This test does not validate WebAuthn behavior. It makes dependency breakage
 * visible before the application starts relying on the library in security code.
 */
final class WebAuthnDependencyTest extends TestCase
{
    /**
     * @return void
     */
    public function testWebAuthnCoreClassesAreAvailable(): void
    {
        self::assertTrue(class_exists(PublicKeyCredentialCreationOptions::class));
        self::assertTrue(class_exists(PublicKeyCredentialRequestOptions::class));
        self::assertTrue(class_exists(AuthenticatorAttestationResponseValidator::class));
        self::assertTrue(class_exists(AuthenticatorAssertionResponseValidator::class));
    }
}
