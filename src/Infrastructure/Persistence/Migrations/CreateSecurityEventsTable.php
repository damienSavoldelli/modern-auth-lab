<?php

declare(strict_types=1);

namespace ModernAuthLab\Infrastructure\Persistence\Migrations;

use ModernAuthLab\Infrastructure\Persistence\Migration;

final readonly class CreateSecurityEventsTable implements Migration
{
    public function version(): string
    {
        return '0003_create_security_events_table';
    }

    public function up(): string
    {
        return <<<'SQL'
            -- Minimal audit schema for authentication-sensitive events.
            -- Payloads stay intentionally narrow until retention and privacy
            -- rules are defined.
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                type TEXT NOT NULL,
                user_id INTEGER NULL,
                email TEXT NULL,
                client_ip TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
            );

            CREATE INDEX IF NOT EXISTS idx_security_events_type ON security_events (type);
            CREATE INDEX IF NOT EXISTS idx_security_events_user_id ON security_events (user_id);
            CREATE INDEX IF NOT EXISTS idx_security_events_email ON security_events (email);
            SQL;
    }
}
