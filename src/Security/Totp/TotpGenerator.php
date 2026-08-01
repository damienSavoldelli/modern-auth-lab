<?php

declare(strict_types=1);

namespace ModernAuthLab\Security\Totp;

use InvalidArgumentException;

/**
 * Generates TOTP codes from a shared secret and a timestamp.
 *
 * TOTP is HOTP where the counter is derived from time:
 * `counter = floor(timestamp / period)`. This class only generates the expected
 * code. User-submitted code verification belongs to the next step.
 */
final readonly class TotpGenerator
{
    private const SUPPORTED_ALGORITHMS = ['SHA1', 'SHA256', 'SHA512'];
    private const SUPPORTED_DIGITS = [6, 8];

    /**
     * Validate TOTP generation parameters.
     *
     * @param string $algorithm HMAC algorithm used for code generation.
     * @param int $digits Number of digits in the generated code.
     * @param int $period Time-step duration in seconds.
     *
     * @throws InvalidArgumentException When generation parameters are invalid.
     */
    public function __construct(
        private string $algorithm = 'SHA1',
        private int $digits = 6,
        private int $period = 30,
    ) {
        if (! in_array($this->algorithm, self::SUPPORTED_ALGORITHMS, true)) {
            throw new InvalidArgumentException('TOTP algorithm must be SHA1, SHA256, or SHA512.');
        }

        if (! in_array($this->digits, self::SUPPORTED_DIGITS, true)) {
            throw new InvalidArgumentException('TOTP digits must be 6 or 8.');
        }

        if ($this->period < 1) {
            throw new InvalidArgumentException('TOTP period must be at least 1 second.');
        }
    }

    /**
     * Generate the TOTP code expected for a secret at a specific timestamp.
     *
     * @param TotpSecret $secret Shared TOTP secret.
     * @param int $timestamp Unix timestamp in seconds.
     *
     * @return string Zero-padded TOTP code.
     *
     * @throws InvalidArgumentException When the timestamp is negative.
     */
    public function generate(TotpSecret $secret, int $timestamp): string
    {
        return $this->generateForTimeStep($secret, $this->timeStep($timestamp));
    }

    /**
     * Generate the TOTP code expected for an already computed time step.
     *
     * @param TotpSecret $secret Shared TOTP secret.
     * @param int $timeStep Time-derived moving factor.
     *
     * @return string Zero-padded TOTP code.
     *
     * @throws InvalidArgumentException When the time step is negative.
     */
    public function generateForTimeStep(TotpSecret $secret, int $timeStep): string
    {
        if ($timeStep < 0) {
            throw new InvalidArgumentException('TOTP time step cannot be negative.');
        }

        return $this->hotp($secret, $timeStep);
    }

    /**
     * Convert a unix timestamp into a TOTP time step.
     *
     * @param int $timestamp Unix timestamp in seconds.
     *
     * @return int Time-derived moving factor.
     *
     * @throws InvalidArgumentException When the timestamp is negative.
     */
    public function timeStep(int $timestamp): int
    {
        if ($timestamp < 0) {
            throw new InvalidArgumentException('TOTP timestamp cannot be negative.');
        }

        return intdiv($timestamp, $this->period);
    }

    /**
     * Generate an HOTP code for the provided counter.
     *
     * @param TotpSecret $secret Shared TOTP secret.
     * @param int $counter Moving factor derived from time.
     *
     * @return string Zero-padded HOTP/TOTP code.
     */
    private function hotp(TotpSecret $secret, int $counter): string
    {
        $hash = hash_hmac(
            strtolower($this->algorithm),
            $this->packCounter($counter),
            $secret->bytes(),
            true,
        );
        $offset = ord($hash[strlen($hash) - 1]) & 0x0f;
        $binary = (
            ((ord($hash[$offset]) & 0x7f) << 24)
            | ((ord($hash[$offset + 1]) & 0xff) << 16)
            | ((ord($hash[$offset + 2]) & 0xff) << 8)
            | (ord($hash[$offset + 3]) & 0xff)
        );
        $modulo = 10 ** $this->digits;

        return str_pad((string) ($binary % $modulo), $this->digits, '0', STR_PAD_LEFT);
    }

    /**
     * Pack the counter as an unsigned 64-bit big-endian integer for HOTP.
     *
     * @param int $counter Moving factor derived from time.
     *
     * @return string Binary counter representation.
     */
    private function packCounter(int $counter): string
    {
        return pack('N2', intdiv($counter, 0x100000000), $counter & 0xffffffff);
    }
}
