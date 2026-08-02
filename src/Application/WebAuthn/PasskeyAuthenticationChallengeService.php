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
 * Starts a Passkey authentication ceremony for a known user.
 *
 * This prepares the Password + Passkey flow for v0.9. It does not mark the
 * session as authenticated and does not verify assertions yet.
 */
final readonly class PasskeyAuthenticationChallengeService
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
     * Create an authentication challenge and browser request options.
     *
     * @param User $user Known user attempting Passkey authentication.
     *
     * @return PasskeyAuthenticationChallengeResult Persisted challenge and public-key options.
     *
     * @throws \RuntimeException When the user has no active Passkey credentials.
     * @throws \Random\RandomException When secure random bytes cannot be generated.
     */
    public function start(User $user): PasskeyAuthenticationChallengeResult
    {
        $activeCredentials = $this->credentials->findActiveByUserId($user->id);

        if ($activeCredentials === []) {
            throw new \RuntimeException('Passkey authentication requires at least one active credential.');
        }

        $challenge = Base64Url::encode(random_bytes(self::CHALLENGE_BYTES));
        $expiresAt = (new DateTimeImmutable())->modify(sprintf('+%d seconds', $this->config->challengeTtlSeconds));
        $record = $this->challenges->create($user->id, 'authentication', $challenge, $expiresAt);

        return new PasskeyAuthenticationChallengeResult(
            $record,
            [
                'challenge' => $challenge,
                'rpId' => $this->config->rpId,
                'allowCredentials' => array_map(
                    static fn($credential): array => [
                        'id' => $credential->credentialId,
                        'type' => 'public-key',
                        'transports' => $credential->transports,
                    ],
                    $activeCredentials,
                ),
                'userVerification' => $this->config->userVerification,
                'timeout' => $this->config->timeoutMs,
                'hints' => ['client-device', 'security-key', 'hybrid'],
            ],
        );
    }
}
