<?php

declare(strict_types=1);

namespace ModernAuthLab\Application\Totp;

use ModernAuthLab\Infrastructure\Persistence\UserTotpCredentialRepository;
use ModernAuthLab\Security\Totp\ProtectedTotpSecret;
use ModernAuthLab\Security\Totp\TotpGenerator;
use ModernAuthLab\Security\Totp\TotpSecretProtector;
use ModernAuthLab\Security\Totp\TotpVerifier;

/**
 * Application service that verifies a TOTP code during login.
 *
 * The service coordinates persistence, secret decryption, and pure TOTP
 * verification. It does not change PHP session state and does not render HTTP
 * responses, keeping login orchestration outside the cryptographic boundary.
 */
final readonly class TotpLoginVerificationService
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
     * Verify a submitted TOTP code for the user's active credential.
     *
     * @param int $userId User id carried by the MFA-pending session.
     * @param string $submittedCode User-submitted authenticator code.
     * @param int|null $timestamp Server-observed unix timestamp, injectable for tests.
     *
     * @return TotpLoginVerificationResult Generic success/failure result.
     */
    public function verify(int $userId, string $submittedCode, ?int $timestamp = null): TotpLoginVerificationResult
    {
        $credential = $this->credentials->findActiveByUserId($userId);
        if ($credential === null) {
            return TotpLoginVerificationResult::failure();
        }

        $secret = $this->secretProtector->reveal(new ProtectedTotpSecret(
            $credential->secretCiphertext,
            $credential->secretNonce,
            $credential->secretKeyId,
        ));
        $verifier = new TotpVerifier(new TotpGenerator($credential->algorithm, $credential->digits, $credential->period));
        $result = $verifier->verify($secret, $submittedCode, $timestamp ?? time());

        if (! $result->success || $result->timeStep === null) {
            return TotpLoginVerificationResult::failure();
        }

        $this->credentials->recordLastUsedTimeStep($credential->id, $result->timeStep);

        return TotpLoginVerificationResult::success($result->timeStep);
    }
}
