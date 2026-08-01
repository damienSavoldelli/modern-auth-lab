<?php

declare(strict_types=1);

namespace ModernAuthLab\Infrastructure\Persistence\Migrations;

use ModernAuthLab\Infrastructure\Persistence\Migration;

/**
 * Creates recovery-code storage for lost-authenticator TOTP recovery.
 *
 * Recovery codes are security-critical credentials. The table stores one-way
 * hashes only and tracks lifecycle state so each code can become single-use.
 */
final readonly class CreateUserTotpRecoveryCodesTable implements Migration
{
    /**
     * Return the stable schema version for TOTP recovery-code persistence.
     *
     * @return string Migration version.
     */
    public function version(): string
    {
        return '0005_create_user_totp_recovery_codes_table';
    }

    /**
     * Return SQL for recovery-code storage and lookup indexes.
     *
     * @return string Migration SQL.
     */
    public function up(): string
    {
        return <<<'SQL'
            CREATE TABLE IF NOT EXISTS user_totp_recovery_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                code_hash TEXT NOT NULL,
                status TEXT NOT NULL,
                used_at TEXT NULL,
                revoked_at TEXT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                CHECK (status IN ('active', 'used', 'revoked'))
            );

            CREATE INDEX IF NOT EXISTS idx_user_totp_recovery_codes_user_id
                ON user_totp_recovery_codes (user_id);

            CREATE INDEX IF NOT EXISTS idx_user_totp_recovery_codes_status
                ON user_totp_recovery_codes (status);

            CREATE UNIQUE INDEX IF NOT EXISTS uq_user_totp_recovery_codes_hash
                ON user_totp_recovery_codes (code_hash);
            SQL;
    }
}
