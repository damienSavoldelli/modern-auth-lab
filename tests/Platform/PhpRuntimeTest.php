<?php

declare(strict_types=1);

namespace ModernAuthLab\Tests\Platform;

use PHPUnit\Framework\TestCase;

final class PhpRuntimeTest extends TestCase
{
    public function testProjectRequiresPhp85OrNewer(): void
    {
        self::assertGreaterThanOrEqual(80500, PHP_VERSION_ID);
    }
}
