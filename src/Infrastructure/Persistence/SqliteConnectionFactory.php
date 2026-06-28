<?php

declare(strict_types=1);

namespace ModernAuthLab\Infrastructure\Persistence;

use PDO;
use RuntimeException;

/**
 * Opens the local SQLite connection used by the application.
 *
 * The factory centralizes PDO safety defaults so repositories do not need to
 * configure error handling, fetch mode, prepared statements, or foreign keys.
 */
final readonly class SqliteConnectionFactory
{
    /**
     * Receive the SQLite database configuration.
     *
     * @param DatabaseConfig $config SQLite database configuration.
     */
    public function __construct(
        private DatabaseConfig $config,
    ) {}

    /**
     * Create a configured PDO connection and ensure the database directory exists.
     *
     * @return PDO Configured SQLite PDO connection.
     *
     * @throws RuntimeException When the database directory cannot be created.
     * @throws \PDOException When PDO cannot open or configure the database.
     */
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
