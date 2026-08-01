<?php

declare(strict_types=1);

namespace ModernAuthLab\Security\Totp;

/**
 * Immutable result returned by TOTP verification.
 *
 * The accepted time step is exposed only on success so future persistence can
 * store it for replay prevention.
 */
final readonly class TotpVerificationResult
{
    private function __construct(
        public bool $success,
        public ?int $timeStep,
    ) {}

    /**
     * Create a successful verification result.
     *
     * @param int $timeStep Accepted TOTP time step.
     *
     * @return self Successful verification result.
     */
    public static function success(int $timeStep): self
    {
        return new self(true, $timeStep);
    }

    /**
     * Create a failed verification result.
     *
     * @return self Failed verification result without timing detail.
     */
    public static function failure(): self
    {
        return new self(false, null);
    }
}
