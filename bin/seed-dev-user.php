<?php

declare(strict_types=1);

use ModernAuthLab\Application\User\DevUserSeeder;
use ModernAuthLab\Infrastructure\Persistence\DatabaseConfig;
use ModernAuthLab\Infrastructure\Persistence\MigrationRepository;
use ModernAuthLab\Infrastructure\Persistence\MigrationRunner;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateUsersTable;
use ModernAuthLab\Infrastructure\Persistence\SqliteConnectionFactory;
use ModernAuthLab\Infrastructure\Persistence\UserRepository;
use ModernAuthLab\Security\Password\PasswordHasher;

require dirname(__DIR__) . '/vendor/autoload.php';

$pdo = (new SqliteConnectionFactory(DatabaseConfig::default(dirname(__DIR__))))->connect();
$migrationRepository = new MigrationRepository($pdo);

(new MigrationRunner($pdo, $migrationRepository, [new CreateUsersTable()]))->run();

$result = (new DevUserSeeder(
    new UserRepository($pdo),
    new PasswordHasher(),
))->seed();

if ($result->created) {
    echo sprintf(
        "Created dev user:\nEmail: %s\nPassword: %s\n",
        DevUserSeeder::EMAIL,
        DevUserSeeder::PASSWORD,
    );

    exit(0);
}

echo sprintf("Dev user already exists: %s\n", DevUserSeeder::EMAIL);
