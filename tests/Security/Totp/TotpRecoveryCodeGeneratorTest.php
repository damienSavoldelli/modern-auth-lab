<?php

declare(strict_types=1);

namespace ModernAuthLab\Tests\Security\Totp;

use ModernAuthLab\Security\Totp\TotpRecoveryCodeGenerator;
use PHPUnit\Framework\TestCase;

final class TotpRecoveryCodeGeneratorTest extends TestCase
{
    public function testGeneratesHumanReadableRecoveryCode(): void
    {
        $code = (new TotpRecoveryCodeGenerator())->generate();

        self::assertMatchesRegularExpression('/^[A-HJ-NP-Z2-9]{4}(?:-[A-HJ-NP-Z2-9]{4}){3}$/', $code);
    }

    public function testGeneratesUniqueRecoveryCodeList(): void
    {
        $codes = (new TotpRecoveryCodeGenerator())->generateMany(8);

        self::assertCount(8, $codes);
        self::assertCount(8, array_unique($codes));
    }

    public function testRejectsShortRecoveryCodes(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('TOTP recovery codes must contain at least 8 characters.');

        new TotpRecoveryCodeGenerator(characters: 4);
    }

    public function testRejectsInvalidGroupSize(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('TOTP recovery code group size must divide the character count.');

        new TotpRecoveryCodeGenerator(characters: 16, groupSize: 6);
    }

    public function testRejectsEmptyGenerationList(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('At least one TOTP recovery code must be generated.');

        (new TotpRecoveryCodeGenerator())->generateMany(0);
    }
}
