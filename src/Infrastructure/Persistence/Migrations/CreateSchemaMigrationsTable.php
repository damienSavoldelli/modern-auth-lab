<?php

declare(strict_types=1);

namespace ModernAuthLab\Infrastructure\Persistence\Migrations;

use ModernAuthLab\Infrastructure\Persistence\Migration;

final readonly class CreateSchemaMigrationsTable implements Migration
{
    public function version(): string
    {
        return '0001_create_schema_migrations_table';
    }

    public function up(): string
    {
        return <<<'SQL'
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version TEXT PRIMARY KEY,
                applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            SQL;
    }
}
