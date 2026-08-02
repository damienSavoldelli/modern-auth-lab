<?php

declare(strict_types=1);

namespace ModernAuthLab\Infrastructure\Persistence;

/**
 * Immutable WebAuthn challenge row loaded from persistence.
 *
 * A challenge is temporary proof that the server initiated the current
 * enrollment or authentication ceremony for a specific user.
 */
final readonly class WebAuthnChallenge
{
    /**
     * Hydrate a WebAuthn challenge from trusted persistence data.
     *
     * @param int $id Database identifier.
     * @param int $userId User associated with this challenge.
     * @param string $purpose Challenge purpose: enrollment or authentication.
     * @param string $challenge Base64URL-encoded challenge bytes.
     * @param string $expiresAt Expiration timestamp.
     * @param string|null $consumedAt Timestamp when challenge was consumed.
     * @param string $createdAt Creation timestamp from persistence.
     */
    public function __construct(
        public int $id,
        public int $userId,
        public string $purpose,
        public string $challenge,
        public string $expiresAt,
        public ?string $consumedAt,
        public string $createdAt,
    ) {}
}
