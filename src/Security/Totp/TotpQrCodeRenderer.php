<?php

declare(strict_types=1);

namespace ModernAuthLab\Security\Totp;

use chillerlan\QRCode\Common\EccLevel;
use chillerlan\QRCode\QRCode;
use chillerlan\QRCode\QROptions;
use RuntimeException;

/**
 * Renders TOTP provisioning URIs as QR code data URIs.
 *
 * The QR code is a visual transport for the secret-bearing `otpauth://` URI.
 * It must not be persisted or logged.
 */
final readonly class TotpQrCodeRenderer
{
    /**
     * Render an `otpauth://` URI as an inline SVG data URI.
     *
     * @param string $provisioningUri Secret-bearing TOTP provisioning URI.
     *
     * @return string SVG QR code as a `data:image/svg+xml;base64,...` URI.
     */
    public function renderDataUri(string $provisioningUri): string
    {
        $result = (new QRCode(new QROptions([
            'eccLevel' => EccLevel::M,
            'outputBase64' => true,
            'outputType' => QRCode::OUTPUT_MARKUP_SVG,
            'scale' => 6,
        ])))->render($provisioningUri);

        if (! is_string($result) || ! str_starts_with($result, 'data:image/svg+xml;base64,')) {
            throw new RuntimeException('TOTP QR code renderer did not return a valid SVG data URI.');
        }

        return $result;
    }
}
