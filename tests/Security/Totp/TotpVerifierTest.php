<?php

declare(strict_types=1);

namespace ModernAuthLab\Tests\Security\Totp;

use InvalidArgumentException;
use ModernAuthLab\Security\Totp\Base32;
use ModernAuthLab\Security\Totp\TotpGenerator;
use ModernAuthLab\Security\Totp\TotpSecret;
use ModernAuthLab\Security\Totp\TotpVerifier;
use PHPUnit\Framework\TestCase;

final class TotpVerifierTest extends TestCase
{
    public function testAcceptsCurrentTimeStepCode(): void
    {
        $secret = $this->secret();
        $generator = new TotpGenerator();
        $verifier = new TotpVerifier($generator);
        $code = $generator->generate($secret, 59);

        $result = $verifier->verify($secret, $code, 59);

        self::assertTrue($result->success);
        self::assertSame($generator->timeStep(59), $result->timeStep);
    }

    public function testAcceptsPreviousTimeStepWhenWindowAllowsIt(): void
    {
        $secret = $this->secret();
        $generator = new TotpGenerator();
        $verifier = new TotpVerifier($generator, window: 1);
        $previousStepCode = $generator->generateForTimeStep($secret, $generator->timeStep(60) - 1);

        $result = $verifier->verify($secret, $previousStepCode, 60);

        self::assertTrue($result->success);
        self::assertSame(1, $result->timeStep);
    }

    public function testAcceptsNextTimeStepWhenWindowAllowsIt(): void
    {
        $secret = $this->secret();
        $generator = new TotpGenerator();
        $verifier = new TotpVerifier($generator, window: 1);
        $nextStepCode = $generator->generateForTimeStep($secret, $generator->timeStep(59) + 1);

        $result = $verifier->verify($secret, $nextStepCode, 59);

        self::assertTrue($result->success);
        self::assertSame(2, $result->timeStep);
    }

    public function testRejectsCodeOutsideWindow(): void
    {
        $secret = $this->secret();
        $generator = new TotpGenerator();
        $verifier = new TotpVerifier($generator, window: 1);
        $outsideWindowCode = $generator->generateForTimeStep($secret, $generator->timeStep(59) + 2);

        $result = $verifier->verify($secret, $outsideWindowCode, 59);

        self::assertFalse($result->success);
        self::assertNull($result->timeStep);
    }

    public function testZeroWindowOnlyAcceptsCurrentStep(): void
    {
        $secret = $this->secret();
        $generator = new TotpGenerator();
        $verifier = new TotpVerifier($generator, window: 0);
        $previousStepCode = $generator->generateForTimeStep($secret, $generator->timeStep(60) - 1);

        $result = $verifier->verify($secret, $previousStepCode, 60);

        self::assertFalse($result->success);
    }

    public function testRejectsNegativeWindow(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('TOTP verification window cannot be negative.');

        new TotpVerifier(window: -1);
    }

    public function testRejectsNegativeTimestamp(): void
    {
        $verifier = new TotpVerifier();

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('TOTP timestamp cannot be negative.');

        $verifier->verify($this->secret(), '123456', -1);
    }

    private function secret(): TotpSecret
    {
        return TotpSecret::fromBase32(Base32::encode('12345678901234567890'));
    }
}
