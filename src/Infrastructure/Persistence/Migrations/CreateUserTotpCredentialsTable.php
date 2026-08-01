<?php

declare(strict_types=1);

namespace ModernAuthLab\Infrastructure\Persistence\Migrations;

use ModernAuthLab\Infrastructure\Persistence\Migration;

/**
 * Creates the TOTP credential table used by authenticator-app MFA.
 *
 * The table stores encrypted secret material metadata, enrollment parameters,
 * lifecycle state, and the last accepted time step needed for future replay
 * protection.
 */
final readonly class CreateUserTotpCredentialsTable implements Migration
{
    /**
     * Return the stable schema version for TOTP credential persistence.
     *
     * @return string Migration version.
     */
    public function version(): string
    {
        return '0004_create_user_totp_credentials_table';
    }

    /**
     * Return SQL for the TOTP credential table and lookup indexes.
     *
     * @return string Migration SQL.
     */
    public function up(): string
    {
        return <<<'SQL'
            CREATE TABLE IF NOT EXISTS user_totp_credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                secret_ciphertext TEXT NOT NULL,
                secret_nonce TEXT NOT NULL,
                secret_key_id TEXT NOT NULL,
                algorithm TEXT NOT NULL,
                digits INTEGER NOT NULL,
                period INTEGER NOT NULL,
                status TEXT NOT NULL,
                confirmed_at TEXT NULL,
                last_used_time_step INTEGER NULL,
                revoked_at TEXT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                CHECK (status IN ('pending', 'active', 'revoked')),
                CHECK (algorithm IN ('SHA1', 'SHA256', 'SHA512')),
                CHECK (digits IN (6, 8)),
                CHECK (period > 0)
            );

            CREATE INDEX IF NOT EXISTS idx_user_totp_credentials_user_id
                ON user_totp_credentials (user_id);

            CREATE INDEX IF NOT EXISTS idx_user_totp_credentials_status
                ON user_totp_credentials (status);

            CREATE UNIQUE INDEX IF NOT EXISTS uq_user_totp_credentials_current
                ON user_totp_credentials (user_id)
                WHERE status IN ('pending', 'active');
            SQL;
    }
}
