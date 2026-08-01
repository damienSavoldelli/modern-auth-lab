<?php

declare(strict_types=1);

namespace ModernAuthLab\Application\Totp;

use ModernAuthLab\Infrastructure\Persistence\UserTotpRecoveryCodeRepository;
use ModernAuthLab\Security\Totp\TotpRecoveryCodeGenerator;
use ModernAuthLab\Security\Totp\TotpRecoveryCodeHasher;

/**
 * Application service that creates recovery-code sets for TOTP recovery.
 *
 * Creating a new set revokes any currently active recovery codes so the account
 * has one clear usable set at a time.
 */
final readonly class TotpRecoveryCodeService
{
    /**
     * @param UserTotpRecoveryCodeRepository $recoveryCodes Recovery-code persistence boundary.
     * @param TotpRecoveryCodeGenerator $generator Plain recovery-code generator.
     * @param TotpRecoveryCodeHasher $hasher One-way recovery-code hasher.
     */
    public function __construct(
        private UserTotpRecoveryCodeRepository $recoveryCodes,
        private TotpRecoveryCodeGenerator $generator,
        private TotpRecoveryCodeHasher $hasher,
    ) {}

    /**
     * Generate a replacement recovery-code set for a user.
     *
     * @param int $userId Owner user identifier.
     * @param int $count Number of recovery codes to generate.
     *
     * @return TotpRecoveryCodeGenerationResult Plain one-time display codes and stored hash records.
     */
    public function generateForUser(int $userId, int $count = 8): TotpRecoveryCodeGenerationResult
    {
        $this->recoveryCodes->revokeActiveByUserId($userId);

        $plainCodes = $this->generator->generateMany($count);
        $records = [];

        foreach ($plainCodes as $plainCode) {
            $records[] = $this->recoveryCodes->createActive($userId, $this->hasher->hash($plainCode));
        }

        return new TotpRecoveryCodeGenerationResult($plainCodes, $records);
    }
}
