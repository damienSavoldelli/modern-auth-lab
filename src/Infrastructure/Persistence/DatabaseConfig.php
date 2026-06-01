<?php

declare(strict_types=1);

namespace ModernAuthLab\Infrastructure\Persistence;

use InvalidArgumentException;

final readonly class DatabaseConfig
{
    public function __construct(
        public string $path,
    ) {
        if ($this->path === '') {
            throw new InvalidArgumentException('Database path cannot be empty.');
        }
    }

    public static function default(string $projectRoot): self
    {
        return new self(rtrim($projectRoot, DIRECTORY_SEPARATOR) . '/var/data/app.sqlite');
    }
}
