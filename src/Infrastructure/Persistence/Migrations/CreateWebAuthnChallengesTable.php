<?php

declare(strict_types=1);

namespace ModernAuthLab\Infrastructure\Persistence\Migrations;

use ModernAuthLab\Infrastructure\Persistence\Migration;

/**
 * Creates short-lived WebAuthn challenge storage.
 *
 * Challenges are one-time server-generated values used to bind a browser
 * ceremony to the current user and purpose. They are not durable credentials.
 */
final readonly class CreateWebAuthnChallengesTable implements Migration
{
    /**
     * Return the stable schema version for WebAuthn challenge persistence.
     *
     * @return string Migration version.
     */
    public function version(): string
    {
        return '0007_create_webauthn_challenges_table';
    }

    /**
     * Return SQL for WebAuthn challenge storage and lookup indexes.
     *
     * @return string Migration SQL.
     */
    public function up(): string
    {
        return <<<'SQL'
            CREATE TABLE IF NOT EXISTS webauthn_challenges (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                purpose TEXT NOT NULL,
                challenge TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                consumed_at TEXT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                CHECK (purpose IN ('enrollment', 'authentication'))
            );

            CREATE UNIQUE INDEX IF NOT EXISTS uq_webauthn_challenges_challenge
                ON webauthn_challenges (challenge);

            CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_user_purpose
                ON webauthn_challenges (user_id, purpose);

            CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_expires_at
                ON webauthn_challenges (expires_at);
            SQL;
    }
}
