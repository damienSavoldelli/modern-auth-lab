<?php

declare(strict_types=1);

namespace ModernAuthLab\Application\Totp;

use ModernAuthLab\Infrastructure\Persistence\UserTotpCredentialRepository;
use ModernAuthLab\Security\Totp\ProtectedTotpSecret;
use ModernAuthLab\Security\Totp\TotpGenerator;
use ModernAuthLab\Security\Totp\TotpSecretProtector;
use ModernAuthLab\Security\Totp\TotpVerifier;

/**
 * Application service that disables an active TOTP credential.
 *
 * Disabling MFA is security-sensitive: the service requires a valid current
 * authenticator code before revoking the active credential.
 */
final readonly class TotpDisableService
{
    /**
     * @param UserTotpCredentialRepository $credentials TOTP persistence boundary.
     * @param TotpSecretProtector $secretProtector Secret decryption boundary.
     */
    public function __construct(
        private UserTotpCredentialRepository $credentials,
        private TotpSecretProtector $secretProtector,
    ) {}

    /**
     * Disable the user's active TOTP credential after verifying possession.
     *
     * @param int $userId Authenticated user id.
     * @param string $submittedCode Current authenticator code supplied by the user.
     * @param int|null $timestamp Server-observed unix timestamp, injectable for tests.
     *
     * @return bool True when an active credential was verified and revoked.
     */
    public function disable(int $userId, string $submittedCode, ?int $timestamp = null): bool
    {
        $credential = $this->credentials->findActiveByUserId($userId);
        if ($credential === null) {
            return false;
        }

        $secret = $this->secretProtector->reveal(new ProtectedTotpSecret(
            $credential->secretCiphertext,
            $credential->secretNonce,
            $credential->secretKeyId,
        ));
        $verifier = new TotpVerifier(new TotpGenerator($credential->algorithm, $credential->digits, $credential->period));
        $result = $verifier->verify($secret, $submittedCode, $timestamp ?? time());

        if (! $result->success || $result->timeStep === null) {
            return false;
        }

        if ($credential->lastUsedTimeStep !== null && $result->timeStep <= $credential->lastUsedTimeStep) {
            return false;
        }

        $this->credentials->recordLastUsedTimeStep($credential->id, $result->timeStep);
        $this->credentials->revoke($credential->id);

        return true;
    }
}
