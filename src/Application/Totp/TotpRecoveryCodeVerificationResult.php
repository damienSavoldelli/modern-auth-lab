<?php

declare(strict_types=1);

namespace ModernAuthLab\Application\Totp;

/**
 * Immutable result returned after recovery-code verification.
 *
 * The result intentionally avoids exposing the submitted recovery code or the
 * stored hash. Callers only need to know whether a code was accepted.
 */
final readonly class TotpRecoveryCodeVerificationResult
{
    private function __construct(
        public bool $success,
        public ?int $recoveryCodeId,
    ) {}

    /**
     * Create a successful recovery-code verification result.
     *
     * @param int $recoveryCodeId Consumed recovery-code identifier.
     *
     * @return self Successful verification result.
     */
    public static function success(int $recoveryCodeId): self
    {
        return new self(true, $recoveryCodeId);
    }

    /**
     * Create a generic failed recovery-code verification result.
     *
     * @return self Failed verification result.
     */
    public static function failure(): self
    {
        return new self(false, null);
    }
}
