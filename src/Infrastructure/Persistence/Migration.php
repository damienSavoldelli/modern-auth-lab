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
     *
     * @return string Stable migration version.
     */
    public function version(): string;

    /**
     * Return SQL that applies the migration.
     *
     * @return string Migration SQL.
     */
    public function up(): string;
}
