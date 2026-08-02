<?php

declare(strict_types=1);

namespace ModernAuthLab\Infrastructure\Persistence\Migrations;

use ModernAuthLab\Infrastructure\Persistence\Migration;

/**
 * Creates the Passkey credential table used by WebAuthn MFA.
 *
 * The server stores public credential material and lifecycle metadata only.
 * Private keys remain inside the user's authenticator, keychain, password
 * manager, phone, or hardware security key.
 */
final readonly class CreateUserPasskeyCredentialsTable implements Migration
{
    /**
     * Return the stable schema version for Passkey credential persistence.
     *
     * @return string Migration version.
     */
    public function version(): string
    {
        return '0006_create_user_passkey_credentials_table';
    }

    /**
     * Return SQL for the Passkey credential table and lookup indexes.
     *
     * @return string Migration SQL.
     */
    public function up(): string
    {
        return <<<'SQL'
            CREATE TABLE IF NOT EXISTS user_passkey_credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                credential_id TEXT NOT NULL,
                public_key TEXT NOT NULL,
                sign_count INTEGER NOT NULL DEFAULT 0,
                name TEXT NOT NULL,
                transports_json TEXT NOT NULL DEFAULT '[]',
                attestation_type TEXT NULL,
                aaguid TEXT NULL,
                status TEXT NOT NULL,
                last_used_at TEXT NULL,
                revoked_at TEXT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                CHECK (status IN ('active', 'revoked')),
                CHECK (sign_count >= 0),
                CHECK (json_valid(transports_json))
            );

            CREATE UNIQUE INDEX IF NOT EXISTS uq_user_passkey_credentials_credential_id
                ON user_passkey_credentials (credential_id);

            CREATE INDEX IF NOT EXISTS idx_user_passkey_credentials_user_id
                ON user_passkey_credentials (user_id);

            CREATE INDEX IF NOT EXISTS idx_user_passkey_credentials_status
                ON user_passkey_credentials (status);
            SQL;
    }
}
