<?php

declare(strict_types=1);

namespace ModernAuthLab\Application\WebAuthn;

use ModernAuthLab\Infrastructure\Persistence\WebAuthnChallenge;

/**
 * Result returned when the server starts Passkey authentication.
 *
 * The options array is JSON-ready for a future `navigator.credentials.get()`
 * browser call. Binary values are represented as unpadded Base64URL strings.
 */
final readonly class PasskeyAuthenticationChallengeResult
{
    /**
     * @param WebAuthnChallenge $challenge Persisted server challenge.
     * @param array<string, mixed> $publicKeyOptions JSON-ready `publicKey` request options.
     */
    public function __construct(
        public WebAuthnChallenge $challenge,
        public array $publicKeyOptions,
    ) {}
}
