<?php

declare(strict_types=1);

namespace ModernAuthLab\Tests\Security\Totp;

use InvalidArgumentException;
use ModernAuthLab\Security\Totp\ProtectedTotpSecret;
use ModernAuthLab\Security\Totp\TotpSecret;
use ModernAuthLab\Security\Totp\TotpSecretProtector;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class TotpSecretProtectorTest extends TestCase
{
    public function testProtectsAndRevealsTotpSecret(): void
    {
        $secret = TotpSecret::fromBase32('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
        $protector = new TotpSecretProtector(str_repeat('a', 32), 'local');

        $protected = $protector->protect($secret);
        $revealed = $protector->reveal($protected);

        self::assertSame('local', $protected->keyId);
        self::assertNotSame($secret->base32(), $protected->ciphertext);
        self::assertSame($secret->base32(), $revealed->base32());
        self::assertSame($secret->bytes(), $revealed->bytes());
    }

    public function testUsesDifferentNonceForEachProtection(): void
    {
        $secret = TotpSecret::fromBase32('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
        $protector = new TotpSecretProtector(str_repeat('a', 32), 'local');

        $first = $protector->protect($secret);
        $second = $protector->protect($secret);

        self::assertNotSame($first->nonce, $second->nonce);
        self::assertNotSame($first->ciphertext, $second->ciphertext);
    }

    public function testRejectsInvalidEncryptionKeyLength(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('TOTP secret encryption key must contain exactly 32 bytes.');

        new TotpSecretProtector('too-short', 'local');
    }

    public function testRejectsMismatchedKeyId(): void
    {
        $secret = TotpSecret::fromBase32('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
        $protector = new TotpSecretProtector(str_repeat('a', 32), 'local');
        $otherProtector = new TotpSecretProtector(str_repeat('a', 32), 'rotated');

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Protected TOTP secret key id does not match the configured key.');

        $otherProtector->reveal($protector->protect($secret));
    }

    public function testRejectsTamperedCiphertext(): void
    {
        $secret = TotpSecret::fromBase32('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
        $protector = new TotpSecretProtector(str_repeat('a', 32), 'local');
        $protected = $protector->protect($secret);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Protected TOTP secret could not be decrypted.');

        $protector->reveal(new ProtectedTotpSecret(
            base64_encode('tampered'),
            $protected->nonce,
            $protected->keyId,
        ));
    }

    public function testRejectsEmptyProtectedSecretFields(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Protected TOTP secret ciphertext cannot be empty.');

        new ProtectedTotpSecret('', 'nonce', 'local');
    }
}
