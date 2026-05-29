<?php

declare(strict_types=1);

namespace ModernAuthLab\Infrastructure\Persistence;

use PDO;
use RuntimeException;

final readonly class SqliteConnectionFactory
{
    public function __construct(
        private DatabaseConfig $config,
    ) {}

    public function connect(): PDO
    {
        $this->ensureDirectoryExists($this->config->path);

        $pdo = new PDO('sqlite:' . $this->config->path);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
        $pdo->setAttribute(PDO::ATTR_STRINGIFY_FETCHES, false);
        $pdo->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);
        $pdo->exec('PRAGMA foreign_keys = ON');

        return $pdo;
    }

    private function ensureDirectoryExists(string $databasePath): void
    {
        $directory = dirname($databasePath);

        if (is_dir($directory)) {
            return;
        }

        if (! mkdir($directory, 0750, true) && ! is_dir($directory)) {
            throw new RuntimeException(sprintf('Unable to create database directory "%s".', $directory));
        }
    }
}
