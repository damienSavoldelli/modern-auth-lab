<?php

declare(strict_types=1);

namespace ModernAuthLab\Tests\Http\Controller;

use ModernAuthLab\Application\Security\SecurityEventLogger;
use ModernAuthLab\Application\Totp\TotpDisableService;
use ModernAuthLab\Domain\Security\SecurityEventType;
use ModernAuthLab\Http\Controller\AccountSecurityController;
use ModernAuthLab\Infrastructure\Persistence\MigrationRepository;
use ModernAuthLab\Infrastructure\Persistence\MigrationRunner;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateSecurityEventsTable;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateUsersTable;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateUserTotpCredentialsTable;
use ModernAuthLab\Infrastructure\Persistence\SecurityEventRepository;
use ModernAuthLab\Infrastructure\Persistence\UserRepository;
use ModernAuthLab\Infrastructure\Persistence\UserTotpCredentialRepository;
use ModernAuthLab\Security\Csrf\CsrfTokenManager;
use ModernAuthLab\Security\Totp\TotpGenerator;
use ModernAuthLab\Security\Totp\TotpSecret;
use ModernAuthLab\Security\Totp\TotpSecretProtector;
use ModernAuthLab\Session\AuthSession;
use PDO;
use PHPUnit\Framework\TestCase;

final class AccountSecurityControllerTest extends TestCase
{
    public function testRedirectsAnonymousUsersToLogin(): void
    {
        $storage = [];
        $controller = $this->createController($storage);

        $response = $controller->show();

        self::assertSame(303, $response->statusCode);
        self::assertSame(['Location' => '/login'], $response->headers);
    }

    public function testRedirectsAuthenticatedSessionWithoutIdentityToLogin(): void
    {
        $storage = [];
        $session = new AuthSession($storage);
        $session->markFullyAuthenticated();
        $controller = $this->createController($storage);

        $response = $controller->show();

        self::assertSame(303, $response->statusCode);
        self::assertSame(['Location' => '/login'], $response->headers);
    }

    public function testShowsDisabledTotpStatus(): void
    {
        $storage = [];
        $pdo = $this->createMigratedConnection();
        $user = (new UserRepository($pdo))->create('user@example.com', 'password-hash');
        $session = new AuthSession($storage);
        $session->markFullyAuthenticated($user->id, $user->email);
        $controller = $this->createController($storage, new UserTotpCredentialRepository($pdo));

        $response = $controller->show();

        self::assertSame(200, $response->statusCode);
        self::assertStringContainsString('<h1>Account Security</h1>', $response->body);
        self::assertStringContainsString('Status: Disabled', $response->body);
        self::assertStringContainsString('TOTP is not active for this account.', $response->body);
        self::assertStringContainsString('<a href="/account/totp/setup">Set up TOTP</a>', $response->body);
        self::assertStringNotContainsString('/account/security/totp/disable', $response->body);
    }

    public function testShowsActiveTotpStatusWithoutSecretMaterial(): void
    {
        $storage = [];
        $pdo = $this->createMigratedConnection();
        $user = (new UserRepository($pdo))->create('user@example.com', 'password-hash');
        $session = new AuthSession($storage);
        $session->markFullyAuthenticated($user->id, $user->email);
        $credentials = new UserTotpCredentialRepository($pdo);
        $pending = $credentials->createPending(
            $user->id,
            'encrypted-secret',
            'secret-nonce',
            'local-key',
            'SHA1',
            6,
            30,
        );
        $active = $credentials->confirm($pending->id);
        $credentials->recordLastUsedTimeStep($active->id, 123456);
        $controller = $this->createController($storage, $credentials);

        $response = $controller->show();

        self::assertSame(200, $response->statusCode);
        self::assertStringContainsString('Status: Enabled', $response->body);
        self::assertStringContainsString('TOTP is active for this account.', $response->body);
        self::assertStringContainsString('<dd>SHA1</dd>', $response->body);
        self::assertStringContainsString('<dd>6</dd>', $response->body);
        self::assertStringContainsString('<dd>30 seconds</dd>', $response->body);
        self::assertStringContainsString('<dd>123456</dd>', $response->body);
        self::assertStringContainsString('<form method="post" action="/account/security/totp/disable">', $response->body);
        self::assertStringContainsString('name="csrf_token"', $response->body);
        self::assertStringContainsString('Current authenticator code', $response->body);
        self::assertStringContainsString('Disable TOTP', $response->body);
        self::assertArrayHasKey('totp_disable_form', $storage['_csrf_tokens']);
        self::assertStringNotContainsString('encrypted-secret', $response->body);
        self::assertStringNotContainsString('secret-nonce', $response->body);
        self::assertStringNotContainsString('local-key', $response->body);
        self::assertStringNotContainsString('otpauth://', $response->body);
    }

    public function testRejectsDisableWithInvalidCsrfAndRecordsEvent(): void
    {
        $storage = [];
        $pdo = $this->createMigratedConnection();
        $user = (new UserRepository($pdo))->create('user@example.com', 'password-hash');
        $session = new AuthSession($storage);
        $session->markFullyAuthenticated($user->id, 'USER@example.COM');
        $credentials = new UserTotpCredentialRepository($pdo);
        $this->activateTotp($credentials, $user->id, $user->email);
        $events = new SecurityEventRepository($pdo);
        $controller = $this->createController($storage, $credentials);

        $response = $controller->disableTotp(
            [
                'csrf_token' => 'invalid',
                'code' => '123456',
            ],
            new TotpDisableService($credentials, $this->secretProtector()),
            new SecurityEventLogger($events),
            '127.0.0.1',
        );

        self::assertSame(400, $response->statusCode);
        self::assertStringContainsString('Unable to disable TOTP', $response->body);
        self::assertNotNull($credentials->findActiveByUserId($user->id));
        self::assertSame(SecurityEventType::TotpDisableFailed->value, $events->all()[0]['type']);
        self::assertSame('user@example.com', $events->all()[0]['email']);
        self::assertStringNotContainsString('123456', json_encode($events->all(), JSON_THROW_ON_ERROR));
    }

    public function testRejectsDisableWithInvalidCodeAndRecordsEvent(): void
    {
        $storage = [];
        $pdo = $this->createMigratedConnection();
        $user = (new UserRepository($pdo))->create('user@example.com', 'password-hash');
        $session = new AuthSession($storage);
        $session->markFullyAuthenticated($user->id, $user->email);
        $credentials = new UserTotpCredentialRepository($pdo);
        $this->activateTotp($credentials, $user->id, $user->email);
        $events = new SecurityEventRepository($pdo);
        $csrf = new CsrfTokenManager($storage);
        $controller = new AccountSecurityController($session, $credentials, $csrf);
        $token = $csrf->issue('totp_disable_form');

        $response = $controller->disableTotp(
            [
                'csrf_token' => $token->value,
                'code' => '000000',
            ],
            new TotpDisableService($credentials, $this->secretProtector()),
            new SecurityEventLogger($events),
            '127.0.0.1',
        );

        self::assertSame(400, $response->statusCode);
        self::assertStringContainsString('Unable to disable TOTP', $response->body);
        self::assertNotNull($credentials->findActiveByUserId($user->id));
        self::assertSame(SecurityEventType::TotpDisableFailed->value, $events->all()[0]['type']);
    }

    public function testDisablesTotpWithValidCodeAndRecordsEvent(): void
    {
        $storage = [];
        $pdo = $this->createMigratedConnection();
        $user = (new UserRepository($pdo))->create('user@example.com', 'password-hash');
        $session = new AuthSession($storage);
        $session->markFullyAuthenticated($user->id, $user->email);
        $credentials = new UserTotpCredentialRepository($pdo);
        $secret = $this->activateTotp($credentials, $user->id, $user->email);
        $events = new SecurityEventRepository($pdo);
        $csrf = new CsrfTokenManager($storage);
        $controller = new AccountSecurityController($session, $credentials, $csrf);
        $token = $csrf->issue('totp_disable_form');
        $code = (new TotpGenerator())->generate($secret, time());

        $response = $controller->disableTotp(
            [
                'csrf_token' => $token->value,
                'code' => $code,
            ],
            new TotpDisableService($credentials, $this->secretProtector()),
            new SecurityEventLogger($events),
            '127.0.0.1',
        );

        self::assertSame(303, $response->statusCode);
        self::assertSame(['Location' => '/account/security'], $response->headers);
        self::assertNull($credentials->findActiveByUserId($user->id));
        self::assertSame(SecurityEventType::TotpDisableSucceeded->value, $events->all()[0]['type']);
        self::assertStringNotContainsString($code, json_encode($events->all(), JSON_THROW_ON_ERROR));
    }

    /**
     * @param array<string, mixed> $storage
     */
    private function createController(
        array &$storage,
        ?UserTotpCredentialRepository $credentials = null,
    ): AccountSecurityController {
        $credentials ??= new UserTotpCredentialRepository($this->createMigratedConnection());

        return new AccountSecurityController(
            new AuthSession($storage),
            $credentials,
            new CsrfTokenManager($storage),
        );
    }

    private function createMigratedConnection(): PDO
    {
        $pdo = new PDO('sqlite::memory:');
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
        $pdo->exec('PRAGMA foreign_keys = ON');

        $runner = new MigrationRunner($pdo, new MigrationRepository($pdo), [
            new CreateUsersTable(),
            new CreateSecurityEventsTable(),
            new CreateUserTotpCredentialsTable(),
        ]);
        $runner->run();

        return $pdo;
    }

    private function activateTotp(UserTotpCredentialRepository $credentials, int $userId, string $email): TotpSecret
    {
        $secretProtector = $this->secretProtector();
        $enrollment = new \ModernAuthLab\Application\Totp\TotpEnrollmentService($credentials, $secretProtector);
        $pending = $enrollment->start($userId, $email);
        $secret = TotpSecret::fromBase32($pending->secretBase32);
        $code = (new TotpGenerator())->generate($secret, 59);

        self::assertTrue($enrollment->confirm($userId, $code, 59));

        return $secret;
    }

    private function secretProtector(): TotpSecretProtector
    {
        return new TotpSecretProtector(str_repeat('a', 32), 'local');
    }
}
