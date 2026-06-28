<?php

declare(strict_types=1);

namespace ModernAuthLab\Infrastructure\Persistence;

/**
 * Contract for an append-only SQLite schema migration.
 *
 * Migrations are intentionally simple SQL providers so early persistence logic
 * remains transparent and reviewable.
 */
interface Migration
{
    /**
     * Return the stable migration identifier stored in schema_migrations.
     */
    public function version(): string;

    /**
     * Return SQL that applies the migration.
     */
    public function up(): string;
}
