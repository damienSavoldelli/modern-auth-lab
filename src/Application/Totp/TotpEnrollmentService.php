<?php

declare(strict_types=1);

namespace ModernAuthLab\Application\Totp;

use ModernAuthLab\Infrastructure\Persistence\UserTotpCredential;
use ModernAuthLab\Infrastructure\Persistence\UserTotpCredentialRepository;
use ModernAuthLab\Security\Totp\ProtectedTotpSecret;
use ModernAuthLab\Security\Totp\TotpProvisioningUri;
use ModernAuthLab\Security\Totp\TotpSecret;
use ModernAuthLab\Security\Totp\TotpSecretProtector;
use RuntimeException;

/**
 * Application service that starts or resumes TOTP enrollment.
 *
 * It coordinates pure TOTP primitives with persistence. HTTP controllers remain
 * responsible for authentication checks and rendering.
 */
final readonly class TotpEnrollmentService
{
    private const DEFAULT_ALGORITHM = 'SHA1';
    private const DEFAULT_DIGITS = 6;
    private const DEFAULT_PERIOD = 30;

    /**
     * @param UserTotpCredentialRepository $credentials TOTP persistence boundary.
     * @param TotpSecretProtector $secretProtector Secret encryption boundary.
     * @param string $issuer Service name shown inside authenticator apps.
     */
    public function __construct(
        private UserTotpCredentialRepository $credentials,
        private TotpSecretProtector $secretProtector,
        private string $issuer = 'Modern Auth Lab',
    ) {}

    /**
     * Start a new pending enrollment or resume an existing pending enrollment.
     *
     * @param int $userId Authenticated user id.
     * @param string $accountLabel Account label shown inside authenticator apps.
     *
     * @return TotpEnrollmentStartResult Pending credential plus provisioning URI.
     *
     * @throws RuntimeException When the user already has active TOTP.
     */
    public function start(int $userId, string $accountLabel): TotpEnrollmentStartResult
    {
        $activeCredential = $this->credentials->findActiveByUserId($userId);
        if ($activeCredential !== null) {
            throw new RuntimeException('TOTP is already active for this user.');
        }

        $pendingCredential = $this->credentials->findPendingByUserId($userId);
        if ($pendingCredential !== null) {
            return $this->resultFromExistingPendingCredential($pendingCredential, $accountLabel);
        }

        $secret = TotpSecret::generate();
        $protectedSecret = $this->secretProtector->protect($secret);
        $credential = $this->credentials->createPending(
            $userId,
            $protectedSecret->ciphertext,
            $protectedSecret->nonce,
            $protectedSecret->keyId,
            self::DEFAULT_ALGORITHM,
            self::DEFAULT_DIGITS,
            self::DEFAULT_PERIOD,
        );

        return new TotpEnrollmentStartResult(
            $credential,
            $this->provisioningUri($secret, $credential, $accountLabel),
            $secret->base32(),
            true,
        );
    }

    private function resultFromExistingPendingCredential(
        UserTotpCredential $credential,
        string $accountLabel,
    ): TotpEnrollmentStartResult {
        $secret = $this->secretProtector->reveal(new ProtectedTotpSecret(
            $credential->secretCiphertext,
            $credential->secretNonce,
            $credential->secretKeyId,
        ));

        return new TotpEnrollmentStartResult(
            $credential,
            $this->provisioningUri($secret, $credential, $accountLabel),
            $secret->base32(),
            false,
        );
    }

    private function provisioningUri(TotpSecret $secret, UserTotpCredential $credential, string $accountLabel): string
    {
        return (new TotpProvisioningUri(
            $this->issuer,
            $accountLabel,
            $secret,
            $credential->algorithm,
            $credential->digits,
            $credential->period,
        ))->uri();
    }
}
