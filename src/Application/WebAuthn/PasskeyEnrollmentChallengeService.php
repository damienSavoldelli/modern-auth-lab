<?php

declare(strict_types=1);

namespace ModernAuthLab\Application\WebAuthn;

use DateTimeImmutable;
use ModernAuthLab\Domain\User\User;
use ModernAuthLab\Infrastructure\Persistence\UserPasskeyCredentialRepository;
use ModernAuthLab\Infrastructure\Persistence\WebAuthnChallengeRepository;
use ModernAuthLab\Security\WebAuthn\Base64Url;
use ModernAuthLab\Security\WebAuthn\WebAuthnConfig;

/**
 * Starts a Passkey enrollment ceremony for an existing authenticated user.
 *
 * The service creates the server challenge and returns JSON-ready options for
 * a future `navigator.credentials.create()` browser call.
 */
final readonly class PasskeyEnrollmentChallengeService
{
    private const CHALLENGE_BYTES = 32;

    /**
     * @param WebAuthnConfig $config Server-side WebAuthn configuration.
     * @param WebAuthnChallengeRepository $challenges Challenge persistence.
     * @param UserPasskeyCredentialRepository $credentials Existing Passkey credential persistence.
     */
    public function __construct(
        private WebAuthnConfig $config,
        private WebAuthnChallengeRepository $challenges,
        private UserPasskeyCredentialRepository $credentials,
    ) {}

    /**
     * Create an enrollment challenge and browser creation options.
     *
     * @param User $user Fully authenticated user adding a Passkey.
     *
     * @return PasskeyEnrollmentChallengeResult Persisted challenge and public-key options.
     *
     * @throws \Random\RandomException When secure random bytes cannot be generated.
     */
    public function start(User $user): PasskeyEnrollmentChallengeResult
    {
        $challenge = Base64Url::encode(random_bytes(self::CHALLENGE_BYTES));
        $expiresAt = (new DateTimeImmutable())->modify(sprintf('+%d seconds', $this->config->challengeTtlSeconds));
        $record = $this->challenges->create($user->id, 'enrollment', $challenge, $expiresAt);

        return new PasskeyEnrollmentChallengeResult(
            $record,
            $this->publicKeyOptions($user, $challenge),
        );
    }

    /**
     * Build JSON-ready WebAuthn creation options for the browser.
     *
     * @param User $user User adding a Passkey.
     * @param string $challenge Base64URL-encoded challenge.
     *
     * @return array<string, mixed> Browser-facing public-key creation options.
     */
    private function publicKeyOptions(User $user, string $challenge): array
    {
        return [
            'rp' => [
                'id' => $this->config->rpId,
                'name' => $this->config->rpName,
            ],
            'user' => [
                'id' => Base64Url::encode(sprintf('user:%d', $user->id)),
                'name' => $user->email,
                'displayName' => $user->email,
            ],
            'challenge' => $challenge,
            'pubKeyCredParams' => [
                ['type' => 'public-key', 'alg' => -7],
                ['type' => 'public-key', 'alg' => -257],
            ],
            'timeout' => $this->config->timeoutMs,
            'attestation' => 'none',
            'authenticatorSelection' => [
                'residentKey' => 'preferred',
                'userVerification' => $this->config->userVerification,
            ],
            'excludeCredentials' => $this->excludeCredentials($user->id),
            'hints' => ['client-device', 'security-key', 'hybrid'],
        ];
    }

    /**
     * Exclude credentials already registered for this user.
     *
     * @param int $userId User adding a Passkey.
     *
     * @return list<array{id: string, type: string, transports: list<string>}>
     */
    private function excludeCredentials(int $userId): array
    {
        return array_map(
            static fn($credential): array => [
                'id' => $credential->credentialId,
                'type' => 'public-key',
                'transports' => $credential->transports,
            ],
            $this->credentials->findActiveByUserId($userId),
        );
    }
}
