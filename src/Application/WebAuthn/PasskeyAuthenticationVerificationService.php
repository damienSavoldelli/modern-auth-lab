<?php

declare(strict_types=1);

namespace ModernAuthLab\Application\WebAuthn;

use DateTimeImmutable;
use ModernAuthLab\Infrastructure\Persistence\UserPasskeyCredentialRepository;
use ModernAuthLab\Infrastructure\Persistence\WebAuthnChallengeRepository;
use ModernAuthLab\Security\WebAuthn\PasskeyAssertionVerifier;

/**
 * Verifies a Passkey authentication assertion and updates credential state.
 *
 * The service owns application workflow rules around challenge lookup,
 * expiration, credential ownership, sign-counter persistence, and challenge
 * consumption. The verifier owns WebAuthn protocol validation.
 */
final readonly class PasskeyAuthenticationVerificationService
{
    /**
     * @param WebAuthnChallengeRepository $challenges Challenge persistence.
     * @param UserPasskeyCredentialRepository $credentials Passkey credential persistence.
     * @param PasskeyAssertionVerifier $verifier WebAuthn protocol verifier.
     */
    public function __construct(
        private WebAuthnChallengeRepository $challenges,
        private UserPasskeyCredentialRepository $credentials,
        private PasskeyAssertionVerifier $verifier,
    ) {}

    /**
     * Verify a browser assertion for the expected user and update credential state.
     *
     * @param int $expectedUserId User identifier the current login attempt is bound to.
     * @param string $challenge Base64URL challenge echoed by the browser response.
     * @param array<string, mixed> $assertion Browser assertion payload.
     *
     * @return PasskeyAuthenticationVerificationResult Verified credential result.
     *
     * @throws \RuntimeException When the challenge is unknown, expired, or the credential does not belong to the user.
     */
    public function verify(int $expectedUserId, string $challenge, array $assertion): PasskeyAuthenticationVerificationResult
    {
        $challengeRecord = $this->challenges->findUnconsumed($expectedUserId, 'authentication', $challenge);

        if ($challengeRecord === null) {
            throw new \RuntimeException('Passkey authentication challenge was not found.');
        }

        if (new DateTimeImmutable($challengeRecord->expiresAt) <= new DateTimeImmutable()) {
            throw new \RuntimeException('Passkey authentication challenge has expired.');
        }

        $credentialId = $this->credentialIdFromAssertion($assertion);
        $credential = $this->credentials->findActiveByCredentialId($credentialId);

        if ($credential === null) {
            throw new \RuntimeException('Passkey credential was not found.');
        }

        if ($credential->userId !== $expectedUserId) {
            throw new \RuntimeException('Passkey credential does not belong to the current login attempt.');
        }

        $verified = $this->verifier->verify($credential, $challenge, $assertion);
        $updated = $this->credentials->recordSuccessfulUse($credential->id, $verified->signCount);
        $this->challenges->consume($challengeRecord->id);

        return new PasskeyAuthenticationVerificationResult($updated->userId, $updated);
    }

    /**
     * Extract the stored credential id (`id` field) from a browser assertion payload.
     *
     * @param array<string, mixed> $assertion Browser assertion payload.
     */
    private function credentialIdFromAssertion(array $assertion): string
    {
        $id = $assertion['id'] ?? null;

        if (! is_string($id) || $id === '') {
            throw new \RuntimeException('Passkey assertion is missing a credential id.');
        }

        return $id;
    }
}
