<?php

declare(strict_types=1);

use ModernAuthLab\Http\Response;
use ModernAuthLab\Http\Controller\AccountController;
use ModernAuthLab\Http\Controller\AccountSecurityController;
use ModernAuthLab\Http\Controller\LogoutController;
use ModernAuthLab\Http\Controller\PasskeyEnrollmentController;
use ModernAuthLab\Http\Controller\PasswordLoginController;
use ModernAuthLab\Http\Controller\TotpChallengeController;
use ModernAuthLab\Http\Controller\TotpSetupController;
use ModernAuthLab\Http\Router;
use ModernAuthLab\Application\Auth\PasswordAuthenticator;
use ModernAuthLab\Application\Security\SecurityEventLogger;
use ModernAuthLab\Application\Totp\TotpDisableService;
use ModernAuthLab\Application\Totp\TotpEnrollmentService;
use ModernAuthLab\Application\Totp\TotpLoginVerificationService;
use ModernAuthLab\Application\Totp\TotpRecoveryCodeService;
use ModernAuthLab\Application\WebAuthn\PasskeyEnrollmentChallengeService;
use ModernAuthLab\Application\WebAuthn\PasskeyEnrollmentVerificationService;
use ModernAuthLab\Infrastructure\Persistence\DatabaseConfig;
use ModernAuthLab\Infrastructure\Persistence\MigrationRepository;
use ModernAuthLab\Infrastructure\Persistence\MigrationRunner;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateSecurityEventsTable;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateUserPasskeyCredentialsTable;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateUserTotpRecoveryCodesTable;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateUserTotpCredentialsTable;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateWebAuthnChallengesTable;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateUsersTable;
use ModernAuthLab\Infrastructure\Persistence\SecurityEventRepository;
use ModernAuthLab\Infrastructure\Persistence\SqliteConnectionFactory;
use ModernAuthLab\Infrastructure\Persistence\UserPasskeyCredentialRepository;
use ModernAuthLab\Infrastructure\Persistence\UserRepository;
use ModernAuthLab\Infrastructure\Persistence\UserTotpCredentialRepository;
use ModernAuthLab\Infrastructure\Persistence\UserTotpRecoveryCodeRepository;
use ModernAuthLab\Infrastructure\Persistence\WebAuthnChallengeRepository;
use ModernAuthLab\Security\Csrf\CsrfTokenManager;
use ModernAuthLab\Security\Password\PasswordHasher;
use ModernAuthLab\Security\RateLimit\LoginRateLimiter;
use ModernAuthLab\Security\Totp\TotpChallengeRateLimiter;
use ModernAuthLab\Security\Totp\TotpQrCodeRenderer;
use ModernAuthLab\Security\Totp\TotpRateLimitConfig;
use ModernAuthLab\Security\Totp\TotpRecoveryCodeGenerator;
use ModernAuthLab\Security\Totp\TotpRecoveryCodeHasher;
use ModernAuthLab\Security\Totp\TotpSecretEncryptionConfig;
use ModernAuthLab\Security\WebAuthn\WebAuthnConfig;
use ModernAuthLab\Security\WebAuthn\WebAuthnLibPasskeyAttestationVerifier;
use ModernAuthLab\Session\NativeSession;
use ModernAuthLab\Session\SessionCookieOptions;
use ModernAuthLab\Support\EnvLoader;

require dirname(__DIR__) . '/vendor/autoload.php';

EnvLoader::loadIfExists(dirname(__DIR__) . '/.env.local');

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

$router->get('/login/totp', static function (): Response {
    $controller = createTotpChallengeController();

    return $controller->show();
});

$router->post('/login/totp', static function (): Response {
    $controller = createTotpChallengeController();

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

$router->get('/account/security', static function (): Response {
    [, $authSession] = createSessionContext();
    $pdo = createApplicationConnection();

    $controller = new AccountSecurityController(
        $authSession,
        new UserTotpCredentialRepository($pdo),
        new UserPasskeyCredentialRepository($pdo),
        new CsrfTokenManager($_SESSION),
    );

    return $controller->show();
});

$router->post('/account/security/totp/disable', static function (): Response {
    try {
        $controller = createAccountSecurityController();
        $totpConfig = TotpSecretEncryptionConfig::fromEnvironment(getenvArray());
    } catch (\InvalidArgumentException) {
        return Response::html(<<<'HTML'
            <!doctype html>
            <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Account Security - Modern Auth Lab</title>
                </head>
                <body>
                    <main>
                        <h1>Account Security</h1>
                        <p>TOTP lifecycle actions are not configured.</p>
                    </main>
                </body>
            </html>
            HTML, 500);
    }

    $pdo = createApplicationConnection();

    return $controller->disableTotp(
        $_POST,
        new TotpDisableService(
            new UserTotpCredentialRepository($pdo),
            $totpConfig->protector(),
        ),
        new SecurityEventLogger(new SecurityEventRepository($pdo)),
        clientIp(),
    );
});

$router->post('/account/security/totp/recovery-codes/generate', static function (): Response {
    try {
        $controller = createAccountSecurityController();
        $totpConfig = TotpSecretEncryptionConfig::fromEnvironment(getenvArray());
    } catch (\InvalidArgumentException) {
        return Response::html(<<<'HTML'
            <!doctype html>
            <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Account Security - Modern Auth Lab</title>
                </head>
                <body>
                    <main>
                        <h1>Account Security</h1>
                        <p>TOTP recovery-code actions are not configured.</p>
                    </main>
                </body>
            </html>
            HTML, 500);
    }

    $pdo = createApplicationConnection();
    $totpCredentials = new UserTotpCredentialRepository($pdo);

    return $controller->generateRecoveryCodes(
        $_POST,
        new TotpLoginVerificationService(
            $totpCredentials,
            $totpConfig->protector(),
        ),
        new TotpRecoveryCodeService(
            new UserTotpRecoveryCodeRepository($pdo),
            new TotpRecoveryCodeGenerator(),
            new TotpRecoveryCodeHasher(),
        ),
        new SecurityEventLogger(new SecurityEventRepository($pdo)),
        clientIp(),
    );
});

$router->get('/account/totp/setup', static function (): Response {
    try {
        $controller = createTotpSetupController();
    } catch (\InvalidArgumentException) {
        return Response::html(<<<'HTML'
            <!doctype html>
            <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>TOTP Setup - Modern Auth Lab</title>
                </head>
                <body>
                    <main>
                        <h1>TOTP Setup</h1>
                        <p>TOTP enrollment is not configured.</p>
                    </main>
                </body>
            </html>
            HTML, 500);
    }

    return $controller->show();
});

$router->post('/account/totp/setup', static function (): Response {
    try {
        $controller = createTotpSetupController();
    } catch (\InvalidArgumentException) {
        return Response::html(<<<'HTML'
            <!doctype html>
            <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>TOTP Setup - Modern Auth Lab</title>
                </head>
                <body>
                    <main>
                        <h1>TOTP Setup</h1>
                        <p>TOTP enrollment is not configured.</p>
                    </main>
                </body>
            </html>
            HTML, 500);
    }

    return $controller->confirm($_POST);
});

$router->post('/account/security/passkeys/enroll/challenge', static function (): Response {
    try {
        $controller = createPasskeyEnrollmentController();
    } catch (\InvalidArgumentException) {
        return Response::json(['error' => 'not_configured'], 500);
    }

    return $controller->challenge();
});

$router->post('/account/security/passkeys/enroll/verify', static function (): Response {
    try {
        $controller = createPasskeyEnrollmentController();
    } catch (\InvalidArgumentException) {
        return Response::json(['error' => 'not_configured'], 500);
    }

    return $controller->verify(readJsonBody());
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
        new UserTotpCredentialRepository($pdo),
        new UserPasskeyCredentialRepository($pdo),
        new LoginRateLimiter($_SESSION),
        new SecurityEventLogger(new SecurityEventRepository($pdo)),
        clientIp(),
        static fn() => $nativeSession->rotateId(),
    );
}

function createTotpSetupController(): TotpSetupController
{
    [, $authSession] = createSessionContext();
    $pdo = createApplicationConnection();
    $totpConfig = TotpSecretEncryptionConfig::fromEnvironment(getenvArray());

    return new TotpSetupController(
        $authSession,
        new CsrfTokenManager($_SESSION),
        new TotpEnrollmentService(
            new UserTotpCredentialRepository($pdo),
            $totpConfig->protector(),
        ),
        new TotpQrCodeRenderer(),
    );
}

function createTotpChallengeController(): TotpChallengeController
{
    [$nativeSession, $authSession] = createSessionContext();
    $pdo = createApplicationConnection();
    $environment = getenvArray();
    $totpConfig = TotpSecretEncryptionConfig::fromEnvironment($environment);
    $rateLimitConfig = TotpRateLimitConfig::fromEnvironment($environment);

    return new TotpChallengeController(
        $authSession,
        new CsrfTokenManager($_SESSION),
        new TotpLoginVerificationService(
            new UserTotpCredentialRepository($pdo),
            $totpConfig->protector(),
        ),
        new TotpChallengeRateLimiter($_SESSION, $rateLimitConfig),
        new SecurityEventLogger(new SecurityEventRepository($pdo)),
        clientIp(),
        static fn() => $nativeSession->rotateId(),
    );
}

function createPasskeyEnrollmentController(): PasskeyEnrollmentController
{
    [, $authSession] = createSessionContext();
    $pdo = createApplicationConnection();
    $webAuthnConfig = WebAuthnConfig::fromEnvironment(getenvArray());
    $challenges = new WebAuthnChallengeRepository($pdo);
    $credentials = new UserPasskeyCredentialRepository($pdo);

    return new PasskeyEnrollmentController(
        $authSession,
        new UserRepository($pdo),
        new PasskeyEnrollmentChallengeService($webAuthnConfig, $challenges, $credentials),
        new PasskeyEnrollmentVerificationService(
            $challenges,
            $credentials,
            new WebAuthnLibPasskeyAttestationVerifier($webAuthnConfig),
        ),
        new SecurityEventLogger(new SecurityEventRepository($pdo)),
        clientIp(),
    );
}

/**
 * @return array<string, mixed>
 */
function readJsonBody(): array
{
    $raw = file_get_contents('php://input');

    if (! is_string($raw) || $raw === '') {
        return [];
    }

    try {
        /** @var array<string, mixed> $decoded */
        $decoded = json_decode($raw, true, flags: JSON_THROW_ON_ERROR);

        return is_array($decoded) ? $decoded : [];
    } catch (\JsonException) {
        return [];
    }
}

function createAccountSecurityController(): AccountSecurityController
{
    [, $authSession] = createSessionContext();
    $pdo = createApplicationConnection();

    return new AccountSecurityController(
        $authSession,
        new UserTotpCredentialRepository($pdo),
        new UserPasskeyCredentialRepository($pdo),
        new CsrfTokenManager($_SESSION),
    );
}

/**
 * @return array<string, string>
 */
function getenvArray(): array
{
    $environment = getenv();

    return is_array($environment) ? $environment : [];
}

function createApplicationConnection(): \PDO
{
    $pdo = (new SqliteConnectionFactory(DatabaseConfig::default(dirname(__DIR__))))->connect();
    $migrationRepository = new MigrationRepository($pdo);
    (new MigrationRunner($pdo, $migrationRepository, [
        new CreateUsersTable(),
        new CreateSecurityEventsTable(),
        new CreateUserTotpCredentialsTable(),
        new CreateUserTotpRecoveryCodesTable(),
        new CreateUserPasskeyCredentialsTable(),
        new CreateWebAuthnChallengesTable(),
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
