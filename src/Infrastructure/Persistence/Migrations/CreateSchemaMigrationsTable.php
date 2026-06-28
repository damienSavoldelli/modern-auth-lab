<?php

declare(strict_types=1);

namespace ModernAuthLab\Infrastructure\Persistence\Migrations;

use ModernAuthLab\Infrastructure\Persistence\Migration;

/**
 * Creates the migration tracking table.
 *
 * This migration exists for completeness, even though MigrationRepository also
 * defensively creates the same storage before running migrations.
 */
final readonly class CreateSchemaMigrationsTable implements Migration
{
    /**
     * Return the stable schema version for the migration tracking table.
     */
    public function version(): string
    {
        return '0001_create_schema_migrations_table';
    }

    /**
     * Return the SQL for the migration tracking table.
     */
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
