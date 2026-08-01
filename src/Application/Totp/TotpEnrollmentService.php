<?php

declare(strict_types=1);

namespace ModernAuthLab\Application\Totp;

use Closure;
use ModernAuthLab\Infrastructure\Persistence\UserTotpCredential;
use ModernAuthLab\Infrastructure\Persistence\UserTotpCredentialRepository;
use ModernAuthLab\Security\Totp\ProtectedTotpSecret;
use ModernAuthLab\Security\Totp\TotpGenerator;
use ModernAuthLab\Security\Totp\TotpProvisioningUri;
use ModernAuthLab\Security\Totp\TotpSecret;
use ModernAuthLab\Security\Totp\TotpSecretProtector;
use ModernAuthLab\Security\Totp\TotpVerifier;
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
    private const DEFAULT_PENDING_LIFETIME_SECONDS = 1800;

    /**
     * @param UserTotpCredentialRepository $credentials TOTP persistence boundary.
     * @param TotpSecretProtector $secretProtector Secret encryption boundary.
     * @param string $issuer Service name shown inside authenticator apps.
     * @param int $pendingLifetimeSeconds Maximum lifetime for pending enrollments.
     * @param Closure(): int|null $now Optional clock for deterministic tests.
     */
    public function __construct(
        private UserTotpCredentialRepository $credentials,
        private TotpSecretProtector $secretProtector,
        private string $issuer = 'Modern Auth Lab',
        private int $pendingLifetimeSeconds = self::DEFAULT_PENDING_LIFETIME_SECONDS,
        private ?Closure $now = null,
    ) {
        if ($this->pendingLifetimeSeconds < 1) {
            throw new \InvalidArgumentException('TOTP pending enrollment lifetime must be greater than zero.');
        }
    }

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
            if ($this->isExpiredPending($pendingCredential)) {
                $this->credentials->revoke($pendingCredential->id);

                return $this->createPendingEnrollment($userId, $accountLabel);
            }

            return $this->resultFromExistingPendingCredential($pendingCredential, $accountLabel);
        }

        return $this->createPendingEnrollment($userId, $accountLabel);
    }

    /**
     * Create and persist a new pending TOTP enrollment.
     *
     * @param int $userId Authenticated user id.
     * @param string $accountLabel Account label shown inside authenticator apps.
     *
     * @return TotpEnrollmentStartResult Newly created pending enrollment.
     */
    private function createPendingEnrollment(int $userId, string $accountLabel): TotpEnrollmentStartResult
    {
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

    /**
     * Confirm a pending enrollment with the first valid authenticator code.
     *
     * @param int $userId Authenticated user id.
     * @param string $submittedCode Code submitted from the authenticator app.
     * @param int|null $timestamp Server-observed unix timestamp, injectable for tests.
     *
     * @return bool True when the pending credential became active.
     */
    public function confirm(int $userId, string $submittedCode, ?int $timestamp = null): bool
    {
        $credential = $this->credentials->findPendingByUserId($userId);
        if ($credential === null) {
            return false;
        }

        if ($this->isExpiredPending($credential)) {
            $this->credentials->revoke($credential->id);

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

        $this->credentials->recordLastUsedTimeStep($credential->id, $result->timeStep);
        $this->credentials->confirm($credential->id);

        return true;
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

    private function isExpiredPending(UserTotpCredential $credential): bool
    {
        $createdAt = strtotime($credential->createdAt . ' UTC');
        if ($createdAt === false) {
            throw new RuntimeException('TOTP pending credential creation timestamp is invalid.');
        }

        return $createdAt + $this->pendingLifetimeSeconds < $this->now();
    }

    private function now(): int
    {
        if ($this->now !== null) {
            return ($this->now)();
        }

        return time();
    }
}
