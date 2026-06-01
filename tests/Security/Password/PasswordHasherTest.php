<?php

declare(strict_types=1);

namespace ModernAuthLab\Tests\Security\Password;

use ModernAuthLab\Security\Password\PasswordHasher;
use PHPUnit\Framework\TestCase;

final class PasswordHasherTest extends TestCase
{
    public function testHashesAndVerifiesPassword(): void
    {
        $hasher = new PasswordHasher();
        $hash = $hasher->hash('correct horse battery staple');

        self::assertNotSame('correct horse battery staple', $hash);
        self::assertTrue($hasher->verify('correct horse battery staple', $hash));
        self::assertFalse($hasher->verify('wrong password', $hash));
    }

    public function testDetectsWhenHashNeedsRehash(): void
    {
        $lowCostHasher = new PasswordHasher(PASSWORD_BCRYPT, ['cost' => 4]);
        $higherCostHasher = new PasswordHasher(PASSWORD_BCRYPT, ['cost' => 5]);
        $hash = $lowCostHasher->hash('correct horse battery staple');

        self::assertTrue($higherCostHasher->needsRehash($hash));
    }
}
