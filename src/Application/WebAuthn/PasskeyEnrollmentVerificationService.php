<?php

declare(strict_types=1);

namespace ModernAuthLab\Application\WebAuthn;

use DateTimeImmutable;
use ModernAuthLab\Domain\User\User;
use ModernAuthLab\Infrastructure\Persistence\UserPasskeyCredentialRepository;
use ModernAuthLab\Infrastructure\Persistence\WebAuthnChallengeRepository;
use ModernAuthLab\Security\WebAuthn\PasskeyAttestationVerifier;

/**
 * Verifies Passkey enrollment and persists the verified credential.
 *
 * The service owns project workflow rules around challenge lookup, expiration,
 * consumption, naming, and persistence. The verifier owns protocol validation.
 */
final readonly class PasskeyEnrollmentVerificationService
{
    /**
     * @param WebAuthnChallengeRepository $challenges Challenge persistence.
     * @param UserPasskeyCredentialRepository $credentials Passkey credential persistence.
     * @param PasskeyAttestationVerifier $verifier WebAuthn protocol verifier.
     */
    public function __construct(
        private WebAuthnChallengeRepository $challenges,
        private UserPasskeyCredentialRepository $credentials,
        private PasskeyAttestationVerifier $verifier,
    ) {}

    /**
     * Verify a browser enrollment response and store the Passkey credential.
     *
     * @param User $user Existing user enrolling a Passkey.
     * @param string $challenge Base64URL challenge echoed by the browser response.
     * @param array<string, mixed> $credential Browser credential response payload.
     * @param string $name User-facing Passkey name.
     *
     * @return PasskeyEnrollmentVerificationResult Stored credential result.
     */
    public function verify(User $user, string $challenge, array $credential, string $name): PasskeyEnrollmentVerificationResult
    {
        $challengeRecord = $this->challenges->findUnconsumed($user->id, 'enrollment', $challenge);

        if ($challengeRecord === null) {
            throw new \RuntimeException('Passkey enrollment challenge was not found.');
        }

        if (new DateTimeImmutable($challengeRecord->expiresAt) <= new DateTimeImmutable()) {
            throw new \RuntimeException('Passkey enrollment challenge has expired.');
        }

        $verified = $this->verifier->verify($user, $challenge, $credential);
        $stored = $this->credentials->createActive(
            $user->id,
            $verified->credentialId,
            $verified->publicKey,
            $verified->signCount,
            trim($name) === '' ? 'Passkey' : trim($name),
            $verified->transports,
            $verified->attestationType,
            $verified->aaguid,
        );

        $this->challenges->consume($challengeRecord->id);

        return new PasskeyEnrollmentVerificationResult($stored);
    }
}
