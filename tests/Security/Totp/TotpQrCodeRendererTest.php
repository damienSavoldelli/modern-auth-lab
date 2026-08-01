<?php

declare(strict_types=1);

namespace ModernAuthLab\Tests\Security\Totp;

use ModernAuthLab\Security\Totp\TotpQrCodeRenderer;
use PHPUnit\Framework\TestCase;

final class TotpQrCodeRendererTest extends TestCase
{
    public function testRendersProvisioningUriAsSvgDataUri(): void
    {
        $renderer = new TotpQrCodeRenderer();

        $dataUri = $renderer->renderDataUri(
            'otpauth://totp/Modern%20Auth%20Lab:dev%40example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Modern%20Auth%20Lab&algorithm=SHA1&digits=6&period=30',
        );

        self::assertStringStartsWith('data:image/svg+xml;base64,', $dataUri);

        $svg = base64_decode(substr($dataUri, strlen('data:image/svg+xml;base64,')), true);
        self::assertIsString($svg);
        self::assertStringContainsString('<svg', $svg);
        self::assertStringContainsString('</svg>', $svg);
    }
}
