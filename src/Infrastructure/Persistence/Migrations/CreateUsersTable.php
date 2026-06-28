<?php

declare(strict_types=1);

namespace ModernAuthLab\Infrastructure\Persistence\Migrations;

use ModernAuthLab\Infrastructure\Persistence\Migration;

/**
 * Creates the users table used by password authentication.
 *
 * The table stores password hashes only. Plain passwords must remain outside
 * persistence and are handled exclusively by password hashing services.
 */
final readonly class CreateUsersTable implements Migration
{
    /**
     * Return the stable schema version for user persistence.
     *
     * @return string Migration version.
     */
    public function version(): string
    {
        return '0002_create_users_table';
    }

    /**
     * Return SQL for users and their email lookup index.
     *
     * @return string Migration SQL.
     */
    public function up(): string
    {
        return <<<'SQL'
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE INDEX IF NOT EXISTS idx_users_email ON users (email);
            SQL;
    }
}
