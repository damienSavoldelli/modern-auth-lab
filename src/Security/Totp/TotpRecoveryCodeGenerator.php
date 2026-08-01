<?php

declare(strict_types=1);

namespace ModernAuthLab\Security\Totp;

/**
 * Generates human-readable recovery codes for lost-authenticator recovery.
 *
 * Recovery codes are shown to the user once and must be stored only as hashes.
 * The alphabet avoids visually confusing characters such as I, O, 0, and 1.
 */
final readonly class TotpRecoveryCodeGenerator
{
    private const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

    /**
     * @param int $characters Number of random characters before grouping.
     * @param int $groupSize Number of characters per display group.
     */
    public function __construct(
        private int $characters = 16,
        private int $groupSize = 4,
    ) {
        if ($this->characters < 8) {
            throw new \InvalidArgumentException('TOTP recovery codes must contain at least 8 characters.');
        }

        if ($this->groupSize < 2 || $this->characters % $this->groupSize !== 0) {
            throw new \InvalidArgumentException('TOTP recovery code group size must divide the character count.');
        }
    }

    /**
     * Generate one recovery code.
     *
     * @return string Human-readable recovery code.
     */
    public function generate(): string
    {
        $alphabetLength = strlen(self::ALPHABET);
        $characters = '';

        for ($index = 0; $index < $this->characters; $index++) {
            $characters .= self::ALPHABET[random_int(0, $alphabetLength - 1)];
        }

        return implode('-', str_split($characters, $this->groupSize));
    }

    /**
     * Generate a list of recovery codes.
     *
     * @param int $count Number of recovery codes to generate.
     *
     * @return list<string> Human-readable recovery codes.
     */
    public function generateMany(int $count): array
    {
        if ($count < 1) {
            throw new \InvalidArgumentException('At least one TOTP recovery code must be generated.');
        }

        $codes = [];

        while (count($codes) < $count) {
            $codes[$this->generate()] = true;
        }

        return array_keys($codes);
    }
}
