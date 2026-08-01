<?php

declare(strict_types=1);

namespace ModernAuthLab\Security\Totp;

use InvalidArgumentException;

/**
 * Verifies submitted TOTP codes against the expected time-step window.
 *
 * Verification accepts a small configurable clock window to account for minor
 * drift between the server clock, the authenticator app clock, and user typing
 * time near a code boundary.
 */
final readonly class TotpVerifier
{
    /**
     * Validate verifier policy.
     *
     * @param TotpGenerator $generator Code generator using the enrollment parameters.
     * @param int $window Number of previous/next time steps accepted around the current step.
     *
     * @throws InvalidArgumentException When the window is negative.
     */
    public function __construct(
        private TotpGenerator $generator = new TotpGenerator(),
        private int $window = 1,
    ) {
        if ($this->window < 0) {
            throw new InvalidArgumentException('TOTP verification window cannot be negative.');
        }
    }

    /**
     * Verify a user-submitted TOTP code.
     *
     * @param TotpSecret $secret Shared TOTP secret.
     * @param string $submittedCode Code submitted by the user.
     * @param int $timestamp Server-observed unix timestamp in seconds.
     *
     * @return TotpVerificationResult Verification outcome and accepted time step.
     *
     * @throws InvalidArgumentException When the timestamp is negative.
     */
    public function verify(TotpSecret $secret, string $submittedCode, int $timestamp): TotpVerificationResult
    {
        $currentStep = $this->generator->timeStep($timestamp);

        for ($timeStep = $currentStep - $this->window; $timeStep <= $currentStep + $this->window; $timeStep++) {
            if ($timeStep < 0) {
                continue;
            }

            if (hash_equals($this->generator->generateForTimeStep($secret, $timeStep), $submittedCode)) {
                return TotpVerificationResult::success($timeStep);
            }
        }

        return TotpVerificationResult::failure();
    }
}
