<?php

declare(strict_types=1);

namespace ModernAuthLab\Application\Totp;

/**
 * Immutable result returned by TOTP login verification.
 *
 * The result intentionally exposes only a success flag and the accepted time
 * step. It does not expose secret material, expected codes, or detailed failure
 * reasons that could leak authentication policy details.
 */
final readonly class TotpLoginVerificationResult
{
    private function __construct(
        public bool $success,
        public ?int $timeStep,
    ) {}

    /**
     * Create a successful TOTP login verification result.
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
     * Create a generic failed TOTP login verification result.
     *
     * @return self Failed verification result.
     */
    public static function failure(): self
    {
        return new self(false, null);
    }
}
