<?php

declare(strict_types=1);

namespace ModernAuthLab\Tests\Http\Controller;

use ModernAuthLab\Application\Totp\TotpEnrollmentService;
use ModernAuthLab\Http\Controller\TotpSetupController;
use ModernAuthLab\Infrastructure\Persistence\MigrationRepository;
use ModernAuthLab\Infrastructure\Persistence\MigrationRunner;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateUsersTable;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateUserTotpCredentialsTable;
use ModernAuthLab\Infrastructure\Persistence\UserRepository;
use ModernAuthLab\Infrastructure\Persistence\UserTotpCredentialRepository;
use ModernAuthLab\Security\Csrf\CsrfTokenManager;
use ModernAuthLab\Security\Totp\TotpGenerator;
use ModernAuthLab\Security\Totp\TotpSecret;
use ModernAuthLab\Security\Totp\TotpSecretProtector;
use ModernAuthLab\Session\AuthSession;
use PDO;
use PHPUnit\Framework\TestCase;

final class TotpSetupControllerTest extends TestCase
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

    public function testShowsSetupPageAndCreatesPendingCredential(): void
    {
        $storage = [];
        $pdo = $this->createMigratedConnection();
        $user = (new UserRepository($pdo))->create('user@example.com', 'password-hash');
        $session = new AuthSession($storage);
        $session->markFullyAuthenticated($user->id, $user->email);
        $credentials = new UserTotpCredentialRepository($pdo);
        $controller = $this->createController($storage, $credentials);

        $response = $controller->show();

        self::assertSame(200, $response->statusCode);
        self::assertStringContainsString('<h1>TOTP Setup</h1>', $response->body);
        self::assertStringContainsString('New pending TOTP enrollment created.', $response->body);
        self::assertStringContainsString('otpauth://totp/', $response->body);
        self::assertStringContainsString('Manual Secret', $response->body);
        self::assertStringContainsString('<form method="post" action="/account/totp/setup">', $response->body);
        self::assertArrayHasKey('totp_setup_form', $storage['_csrf_tokens']);
        self::assertNotNull($credentials->findPendingByUserId($user->id));
    }

    public function testConfirmsPendingCredentialWithValidCode(): void
    {
        $storage = [];
        $pdo = $this->createMigratedConnection();
        $user = (new UserRepository($pdo))->create('user@example.com', 'password-hash');
        $session = new AuthSession($storage);
        $session->markFullyAuthenticated($user->id, $user->email);
        $credentials = new UserTotpCredentialRepository($pdo);
        $controller = $this->createController($storage, $credentials);
        $setupResponse = $controller->show();
        $code = $this->codeFromSetupPage($setupResponse->body);
        $token = (new CsrfTokenManager($storage))->issue('totp_setup_form');

        $response = $controller->confirm([
            'csrf_token' => $token->value,
            'code' => $code,
        ]);

        self::assertSame(303, $response->statusCode);
        self::assertSame(['Location' => '/account'], $response->headers);
        self::assertNull($credentials->findPendingByUserId($user->id));
        self::assertNotNull($credentials->findActiveByUserId($user->id));
    }

    public function testRejectsInvalidConfirmationCode(): void
    {
        $storage = [];
        $pdo = $this->createMigratedConnection();
        $user = (new UserRepository($pdo))->create('user@example.com', 'password-hash');
        $session = new AuthSession($storage);
        $session->markFullyAuthenticated($user->id, $user->email);
        $credentials = new UserTotpCredentialRepository($pdo);
        $controller = $this->createController($storage, $credentials);
        $controller->show();
        $token = (new CsrfTokenManager($storage))->issue('totp_setup_form');

        $response = $controller->confirm([
            'csrf_token' => $token->value,
            'code' => '000000',
        ]);

        self::assertSame(400, $response->statusCode);
        self::assertStringContainsString('Invalid authenticator code.', $response->body);
        self::assertNotNull($credentials->findPendingByUserId($user->id));
        self::assertNull($credentials->findActiveByUserId($user->id));
    }

    public function testRejectsInvalidCsrfDuringConfirmation(): void
    {
        $storage = [];
        $pdo = $this->createMigratedConnection();
        $user = (new UserRepository($pdo))->create('user@example.com', 'password-hash');
        $session = new AuthSession($storage);
        $session->markFullyAuthenticated($user->id, $user->email);
        $credentials = new UserTotpCredentialRepository($pdo);
        $controller = $this->createController($storage, $credentials);
        $controller->show();

        $response = $controller->confirm([
            'csrf_token' => 'invalid',
            'code' => '000000',
        ]);

        self::assertSame(400, $response->statusCode);
        self::assertStringContainsString('Invalid authenticator code.', $response->body);
        self::assertNotNull($credentials->findPendingByUserId($user->id));
    }

    public function testShowsAlreadyActiveMessage(): void
    {
        $storage = [];
        $pdo = $this->createMigratedConnection();
        $user = (new UserRepository($pdo))->create('user@example.com', 'password-hash');
        $session = new AuthSession($storage);
        $session->markFullyAuthenticated($user->id, $user->email);
        $credentials = new UserTotpCredentialRepository($pdo);
        $pending = $credentials->createPending($user->id, 'ciphertext', 'nonce', 'local', 'SHA1', 6, 30);
        $credentials->confirm($pending->id);
        $controller = $this->createController($storage, $credentials);

        $response = $controller->show();

        self::assertSame(200, $response->statusCode);
        self::assertStringContainsString('TOTP is already active for this account.', $response->body);
    }

    /**
     * @param array<string, mixed> $storage
     */
    private function createController(
        array &$storage,
        ?UserTotpCredentialRepository $credentials = null,
    ): TotpSetupController {
        $credentials ??= new UserTotpCredentialRepository($this->createMigratedConnection());

        return new TotpSetupController(
            new AuthSession($storage),
            new CsrfTokenManager($storage),
            new TotpEnrollmentService(
                $credentials,
                new TotpSecretProtector(str_repeat('a', 32), 'local'),
            ),
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
            new CreateUserTotpCredentialsTable(),
        ]);
        $runner->run();

        return $pdo;
    }

    private function codeFromSetupPage(string $body): string
    {
        preg_match('/<code>([A-Z2-7]+)<\\/code>/', $body, $matches);
        self::assertArrayHasKey(1, $matches);

        return (new TotpGenerator())->generate(TotpSecret::fromBase32($matches[1]), time());
    }
}
