<?php

declare(strict_types=1);

namespace ModernAuthLab\Tests\Infrastructure\Persistence;

use InvalidArgumentException;
use ModernAuthLab\Infrastructure\Persistence\DatabaseConfig;
use PHPUnit\Framework\TestCase;

final class DatabaseConfigTest extends TestCase
{
    public function testCreatesDefaultDatabasePathUnderVarData(): void
    {
        $config = DatabaseConfig::default('/project/root');

        self::assertSame('/project/root/var/data/app.sqlite', $config->path);
    }

    public function testRejectsEmptyPath(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Database path cannot be empty.');

        new DatabaseConfig('');
    }
}
