<?php

declare(strict_types=1);

namespace ModernAuthLab\Tests\Security\Totp;

use ModernAuthLab\Security\Totp\TotpRecoveryCodeHasher;
use PHPUnit\Framework\TestCase;

final class TotpRecoveryCodeHasherTest extends TestCase
{
    public function testHashesAndVerifiesRecoveryCode(): void
    {
        $hasher = new TotpRecoveryCodeHasher();
        $hash = $hasher->hash('ABCD-EFGH-JKLM-NPQR');

        self::assertNotSame('ABCD-EFGH-JKLM-NPQR', $hash);
        self::assertTrue($hasher->verify('ABCD-EFGH-JKLM-NPQR', $hash));
        self::assertFalse($hasher->verify('ZZZZ-ZZZZ-ZZZZ-ZZZZ', $hash));
    }

    public function testNormalizesSubmittedRecoveryCode(): void
    {
        $hasher = new TotpRecoveryCodeHasher();
        $hash = $hasher->hash('ABCD-EFGH-JKLM-NPQR');

        self::assertTrue($hasher->verify('abcd efgh jklm npqr', $hash));
    }
}
