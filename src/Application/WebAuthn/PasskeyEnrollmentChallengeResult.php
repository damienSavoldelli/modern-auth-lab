<?php

declare(strict_types=1);

namespace ModernAuthLab\Application\WebAuthn;

use ModernAuthLab\Infrastructure\Persistence\WebAuthnChallenge;

/**
 * Result returned when the server starts Passkey enrollment.
 *
 * The options array is intentionally JSON-ready for the future browser module.
 * Binary values are represented as unpadded Base64URL strings.
 */
final readonly class PasskeyEnrollmentChallengeResult
{
    /**
     * @param WebAuthnChallenge $challenge Persisted server challenge.
     * @param array<string, mixed> $publicKeyOptions JSON-ready `publicKey` creation options.
     */
    public function __construct(
        public WebAuthnChallenge $challenge,
        public array $publicKeyOptions,
    ) {}
}
