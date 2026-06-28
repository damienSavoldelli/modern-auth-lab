<?php

declare(strict_types=1);

namespace ModernAuthLab\Tests\Application\Security;

use ModernAuthLab\Application\Security\SecurityEventLogger;
use ModernAuthLab\Domain\Security\SecurityEventType;
use ModernAuthLab\Infrastructure\Persistence\MigrationRepository;
use ModernAuthLab\Infrastructure\Persistence\MigrationRunner;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateSecurityEventsTable;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateUsersTable;
use ModernAuthLab\Infrastructure\Persistence\SecurityEventRepository;
use PDO;
use PHPUnit\Framework\TestCase;

final class SecurityEventLoggerTest extends TestCase
{
    public function testNormalizesEmailBeforeRecordingEvent(): void
    {
        $repository = new SecurityEventRepository($this->createMigratedConnection());
        $logger = new SecurityEventLogger($repository);

        $logger->record(
            SecurityEventType::PasswordLoginFailed,
            null,
            '  USER@example.COM ',
            '127.0.0.1',
        );

        self::assertSame('user@example.com', $repository->all()[0]['email']);
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
