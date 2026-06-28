<?php

declare(strict_types=1);

namespace ModernAuthLab\Tests\Infrastructure\Persistence;

use ModernAuthLab\Domain\Security\SecurityEventType;
use ModernAuthLab\Infrastructure\Persistence\MigrationRepository;
use ModernAuthLab\Infrastructure\Persistence\MigrationRunner;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateSecurityEventsTable;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateUsersTable;
use ModernAuthLab\Infrastructure\Persistence\SecurityEventRepository;
use PDO;
use PHPUnit\Framework\TestCase;

final class SecurityEventRepositoryTest extends TestCase
{
    public function testRecordsSecurityEvent(): void
    {
        $repository = new SecurityEventRepository($this->createMigratedConnection());

        $repository->record(
            SecurityEventType::PasswordLoginFailed,
            null,
            'user@example.com',
            '127.0.0.1',
        );

        $events = $repository->all();

        self::assertCount(1, $events);
        self::assertSame(SecurityEventType::PasswordLoginFailed->value, $events[0]['type']);
        self::assertNull($events[0]['user_id']);
        self::assertSame('user@example.com', $events[0]['email']);
        self::assertSame('127.0.0.1', $events[0]['client_ip']);
    }

    private function createMigratedConnection(): PDO
    {
        $pdo = new PDO('sqlite::memory:');
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);

        $runner = new MigrationRunner($pdo, new MigrationRepository($pdo), [
            new CreateUsersTable(),
            new CreateSecurityEventsTable(),
        ]);
        $runner->run();

        return $pdo;
    }
}
