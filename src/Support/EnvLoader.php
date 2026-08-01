<?php

declare(strict_types=1);

namespace ModernAuthLab\Support;

use RuntimeException;

/**
 * Minimal dotenv-style loader for local development configuration.
 *
 * The loader intentionally supports only simple `KEY=value` lines. It keeps the
 * project dependency-light while making local demos reproducible through
 * ignored `.env.local` files.
 */
final readonly class EnvLoader
{
    /**
     * Load environment variables from a local file when it exists.
     *
     * Existing process environment values win, so production/runtime
     * configuration can override local files.
     *
     * @param string $path Absolute or relative path to the env file.
     *
     * @return void
     *
     * @throws RuntimeException When the file cannot be read or contains malformed lines.
     */
    public static function loadIfExists(string $path): void
    {
        if (! is_file($path)) {
            return;
        }

        $lines = file($path, FILE_IGNORE_NEW_LINES);
        if ($lines === false) {
            throw new RuntimeException(sprintf('Environment file "%s" cannot be read.', $path));
        }

        foreach ($lines as $lineNumber => $line) {
            self::loadLine($line, $path, $lineNumber + 1);
        }
    }

    private static function loadLine(string $line, string $path, int $lineNumber): void
    {
        $trimmed = trim($line);

        if ($trimmed === '' || str_starts_with($trimmed, '#')) {
            return;
        }

        if (! str_contains($trimmed, '=')) {
            throw new RuntimeException(sprintf('Malformed environment line in "%s" at line %d.', $path, $lineNumber));
        }

        [$name, $value] = explode('=', $trimmed, 2);
        $name = trim($name);

        if ($name === '' || preg_match('/^[A-Z_][A-Z0-9_]*$/', $name) !== 1) {
            throw new RuntimeException(sprintf('Invalid environment variable name in "%s" at line %d.', $path, $lineNumber));
        }

        if (getenv($name) !== false) {
            return;
        }

        $normalizedValue = self::normalizeValue(trim($value));

        putenv($name . '=' . $normalizedValue);
        $_ENV[$name] = $normalizedValue;
        $_SERVER[$name] = $normalizedValue;
    }

    private static function normalizeValue(string $value): string
    {
        if (strlen($value) >= 2 && $value[0] === '"' && $value[strlen($value) - 1] === '"') {
            return stripcslashes(substr($value, 1, -1));
        }

        if (strlen($value) >= 2 && $value[0] === "'" && $value[strlen($value) - 1] === "'") {
            return substr($value, 1, -1);
        }

        return $value;
    }
}
