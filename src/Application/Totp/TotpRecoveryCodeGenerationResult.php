<?php

declare(strict_types=1);

namespace ModernAuthLab\Application\Totp;

use ModernAuthLab\Infrastructure\Persistence\UserTotpRecoveryCode;

/**
 * Result returned after generating a new recovery-code set.
 *
 * Plain recovery codes are intentionally present only in this result so the UI
 * can show them once. Persistence receives only one-way hashes.
 */
final readonly class TotpRecoveryCodeGenerationResult
{
    /**
     * @param list<string> $plainCodes Plain recovery codes to show once.
     * @param list<UserTotpRecoveryCode> $records Persisted hash records.
     */
    public function __construct(
        public array $plainCodes,
        public array $records,
    ) {}
}
