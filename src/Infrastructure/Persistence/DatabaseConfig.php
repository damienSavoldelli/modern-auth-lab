<?php

declare(strict_types=1);

namespace ModernAuthLab\Infrastructure\Persistence;

use InvalidArgumentException;

/**
 * Database connection configuration for the local SQLite runtime.
 *
 * Keeping the path in a value object makes it explicit which filesystem target
 * a factory will open and lets tests validate invalid configuration early.
 */
final readonly class DatabaseConfig
{
    /**
     * Validate the filesystem path used for the SQLite database.
     *
     * @param string $path SQLite database file path.
     *
     * @throws InvalidArgumentException When the path is empty.
     */
    public function __construct(
        public string $path,
    ) {
        if ($this->path === '') {
            throw new InvalidArgumentException('Database path cannot be empty.');
        }
    }

    /**
     * Build the default local database path under the project runtime directory.
     *
     * @param string $projectRoot Absolute or relative project root.
     *
     * @return self Default SQLite configuration.
     */
    public static function default(string $projectRoot): self
    {
        return new self(rtrim($projectRoot, DIRECTORY_SEPARATOR) . '/var/data/app.sqlite');
    }
}
