<?php

declare(strict_types=1);

namespace ModernAuthLab\Tests\Support;

use ModernAuthLab\Support\EnvLoader;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class EnvLoaderTest extends TestCase
{
    protected function tearDown(): void
    {
        putenv('MODERN_AUTH_LAB_TEST_ENV');
        unset($_ENV['MODERN_AUTH_LAB_TEST_ENV'], $_SERVER['MODERN_AUTH_LAB_TEST_ENV']);

        parent::tearDown();
    }

    public function testLoadsSimpleEnvironmentFile(): void
    {
        $path = $this->temporaryEnvFile("MODERN_AUTH_LAB_TEST_ENV=local-value\n");

        EnvLoader::loadIfExists($path);

        self::assertSame('local-value', getenv('MODERN_AUTH_LAB_TEST_ENV'));
        self::assertSame('local-value', $_ENV['MODERN_AUTH_LAB_TEST_ENV']);
        self::assertSame('local-value', $_SERVER['MODERN_AUTH_LAB_TEST_ENV']);
    }

    public function testIgnoresMissingFile(): void
    {
        EnvLoader::loadIfExists(sys_get_temp_dir() . '/modern-auth-lab-missing-env-file');

        self::assertFalse(getenv('MODERN_AUTH_LAB_TEST_ENV'));
    }

    public function testKeepsExistingEnvironmentValue(): void
    {
        putenv('MODERN_AUTH_LAB_TEST_ENV=runtime-value');
        $_ENV['MODERN_AUTH_LAB_TEST_ENV'] = 'runtime-value';
        $_SERVER['MODERN_AUTH_LAB_TEST_ENV'] = 'runtime-value';
        $path = $this->temporaryEnvFile("MODERN_AUTH_LAB_TEST_ENV=local-value\n");

        EnvLoader::loadIfExists($path);

        self::assertSame('runtime-value', getenv('MODERN_AUTH_LAB_TEST_ENV'));
    }

    public function testSupportsQuotedValues(): void
    {
        $path = $this->temporaryEnvFile("MODERN_AUTH_LAB_TEST_ENV=\"local value\"\n");

        EnvLoader::loadIfExists($path);

        self::assertSame('local value', getenv('MODERN_AUTH_LAB_TEST_ENV'));
    }

    public function testRejectsMalformedLine(): void
    {
        $path = $this->temporaryEnvFile("MODERN_AUTH_LAB_TEST_ENV\n");

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Malformed environment line');

        EnvLoader::loadIfExists($path);
    }

    public function testRejectsInvalidVariableName(): void
    {
        $path = $this->temporaryEnvFile("invalid-name=value\n");

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Invalid environment variable name');

        EnvLoader::loadIfExists($path);
    }

    private function temporaryEnvFile(string $contents): string
    {
        $path = tempnam(sys_get_temp_dir(), 'modern-auth-lab-env-');
        self::assertIsString($path);
        file_put_contents($path, $contents);

        return $path;
    }
}
