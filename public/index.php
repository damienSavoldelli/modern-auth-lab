<?php

declare(strict_types=1);

use ModernAuthLab\Http\Response;
use ModernAuthLab\Http\Controller\AccountController;
use ModernAuthLab\Http\Controller\LogoutController;
use ModernAuthLab\Http\Controller\PasswordLoginController;
use ModernAuthLab\Http\Router;
use ModernAuthLab\Application\Auth\PasswordAuthenticator;
use ModernAuthLab\Application\Security\SecurityEventLogger;
use ModernAuthLab\Infrastructure\Persistence\DatabaseConfig;
use ModernAuthLab\Infrastructure\Persistence\MigrationRepository;
use ModernAuthLab\Infrastructure\Persistence\MigrationRunner;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateSecurityEventsTable;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateUsersTable;
use ModernAuthLab\Infrastructure\Persistence\SecurityEventRepository;
use ModernAuthLab\Infrastructure\Persistence\SqliteConnectionFactory;
use ModernAuthLab\Infrastructure\Persistence\UserRepository;
use ModernAuthLab\Security\Csrf\CsrfTokenManager;
use ModernAuthLab\Security\Password\PasswordHasher;
use ModernAuthLab\Security\RateLimit\LoginRateLimiter;
use ModernAuthLab\Session\NativeSession;
use ModernAuthLab\Session\SessionCookieOptions;
use PDO;

require dirname(__DIR__) . '/vendor/autoload.php';

$router = new Router();

$router->get('/health', static fn (): Response => Response::json([
    'status' => 'ok',
    'service' => 'modern-auth-lab',
]));

$router->get('/login', static function (): Response {
    $controller = createPasswordLoginController();

    return $controller->show();
});

$router->post('/login', static function (): Response {
    $controller = createPasswordLoginController();

    return $controller->submit($_POST);
});

$router->get('/account', static function (): Response {
    [, $authSession] = createSessionContext();

    $controller = new AccountController(
        $authSession,
        new CsrfTokenManager($_SESSION),
    );

    return $controller->show();
});

$router->post('/logout', static function (): Response {
    [$nativeSession, $authSession] = createSessionContext();
    $pdo = createApplicationConnection();

    $controller = new LogoutController(
        $authSession,
        new CsrfTokenManager($_SESSION),
        new SecurityEventLogger(new SecurityEventRepository($pdo)),
        clientIp(),
        static fn() => $nativeSession->destroy(),
    );

    return $controller->submit($_POST);
});

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);

if (! is_string($path) || $path === '') {
    $path = '/';
}

$router->dispatch($method, $path)->send();

function createPasswordLoginController(): PasswordLoginController
{
    [$nativeSession, $authSession] = createSessionContext();
    $pdo = createApplicationConnection();

    return new PasswordLoginController(
        new CsrfTokenManager($_SESSION),
        new PasswordAuthenticator(
            new UserRepository($pdo),
            new PasswordHasher(),
        ),
        $authSession,
        new LoginRateLimiter($_SESSION),
        new SecurityEventLogger(new SecurityEventRepository($pdo)),
        clientIp(),
        static fn() => $nativeSession->rotateId(),
    );
}

function createApplicationConnection(): PDO
{
    $pdo = (new SqliteConnectionFactory(DatabaseConfig::default(dirname(__DIR__))))->connect();
    $migrationRepository = new MigrationRepository($pdo);
    (new MigrationRunner($pdo, $migrationRepository, [
        new CreateUsersTable(),
        new CreateSecurityEventsTable(),
    ]))->run();

    return $pdo;
}

/**
 * @return array{0: NativeSession, 1: \ModernAuthLab\Session\AuthSession}
 */
function createSessionContext(): array
{
    $nativeSession = new NativeSession();
    $nativeSession->configure(SessionCookieOptions::forRequest(isHttpsRequest()));

    return [$nativeSession, $nativeSession->auth()];
}

function isHttpsRequest(): bool
{
    $https = $_SERVER['HTTPS'] ?? '';

    return $https === 'on' || $https === '1';
}

function clientIp(): string
{
    $remoteAddress = $_SERVER['REMOTE_ADDR'] ?? '';

    return is_string($remoteAddress) && $remoteAddress !== '' ? $remoteAddress : 'unknown';
}
