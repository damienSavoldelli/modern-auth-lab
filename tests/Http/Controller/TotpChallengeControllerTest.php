<?php

declare(strict_types=1);

namespace ModernAuthLab\Tests\Http\Controller;

use ModernAuthLab\Application\Totp\TotpEnrollmentService;
use ModernAuthLab\Application\Totp\TotpLoginVerificationService;
use ModernAuthLab\Http\Controller\TotpChallengeController;
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
use ModernAuthLab\Session\AuthSessionState;
use PDO;
use PHPUnit\Framework\TestCase;

final class TotpChallengeControllerTest extends TestCase
{
    public function testRedirectsAnonymousUsersToLogin(): void
    {
        $storage = [];
        $controller = new TotpChallengeController(
            new AuthSession($storage),
            new CsrfTokenManager($storage),
            $this->verificationService(),
            static function (): void {},
        );

        $response = $controller->show();

        self::assertSame(303, $response->statusCode);
        self::assertSame(['Location' => '/login'], $response->headers);
    }

    public function testRedirectsFullyAuthenticatedUsersToAccount(): void
    {
        $storage = [];
        $session = new AuthSession($storage);
        $session->markFullyAuthenticated(123, 'user@example.com');
        $controller = new TotpChallengeController(
            $session,
            new CsrfTokenManager($storage),
            $this->verificationService(),
            static function (): void {},
        );

        $response = $controller->show();

        self::assertSame(303, $response->statusCode);
        self::assertSame(['Location' => '/account'], $response->headers);
    }

    public function testRedirectsMfaPendingSessionWithoutUserIdentityToLogin(): void
    {
        $storage = [];
        $session = new AuthSession($storage);
        $session->markMfaPending();
        $controller = new TotpChallengeController(
            $session,
            new CsrfTokenManager($storage),
            $this->verificationService(),
            static function (): void {},
        );

        $response = $controller->show();

        self::assertSame(303, $response->statusCode);
        self::assertSame(['Location' => '/login'], $response->headers);
    }

    public function testShowsChallengeFormForMfaPendingSessionWithUserIdentity(): void
    {
        $storage = [];
        $session = new AuthSession($storage);
        $session->markMfaPending(123, 'user@example.com');
        $controller = new TotpChallengeController(
            $session,
            new CsrfTokenManager($storage),
            $this->verificationService(),
            static function (): void {},
        );

        $response = $controller->show();

        self::assertSame(200, $response->statusCode);
        self::assertStringContainsString('<h1>TOTP Challenge</h1>', $response->body);
        self::assertStringContainsString('<form method="post" action="/login/totp">', $response->body);
        self::assertStringContainsString('name="csrf_token"', $response->body);
        self::assertStringContainsString('autocomplete="one-time-code"', $response->body);
        self::assertArrayHasKey('totp_challenge_form', $storage['_csrf_tokens']);
    }

    public function testRedirectsAnonymousChallengeSubmissionToLogin(): void
    {
        $storage = [];
        $controller = new TotpChallengeController(
            new AuthSession($storage),
            new CsrfTokenManager($storage),
            $this->verificationService(),
            static function (): void {},
        );

        $response = $controller->submit([
            'csrf_token' => 'ignored',
            'code' => '123456',
        ]);

        self::assertSame(303, $response->statusCode);
        self::assertSame(['Location' => '/login'], $response->headers);
    }

    public function testRejectsInvalidCsrfOnChallengeSubmission(): void
    {
        $storage = [];
        $session = new AuthSession($storage);
        $session->markMfaPending(123, 'user@example.com');
        $controller = new TotpChallengeController(
            $session,
            new CsrfTokenManager($storage),
            $this->verificationService(),
            static function (): void {},
        );

        $response = $controller->submit([
            'csrf_token' => 'invalid',
            'code' => '123456',
        ]);

        self::assertSame(400, $response->statusCode);
        self::assertStringContainsString('Invalid authenticator code.', $response->body);
        self::assertArrayHasKey('totp_challenge_form', $storage['_csrf_tokens']);
    }

    public function testRejectsInvalidTotpCode(): void
    {
        $storage = [];
        $session = new AuthSession($storage);
        $session->markMfaPending(123, 'user@example.com');
        $csrf = new CsrfTokenManager($storage);
        $controller = new TotpChallengeController(
            $session,
            $csrf,
            $this->verificationService(),
            static function (): void {},
        );
        $token = $csrf->issue('totp_challenge_form');

        $response = $controller->submit([
            'csrf_token' => $token->value,
            'code' => '123456',
        ]);

        self::assertSame(400, $response->statusCode);
        self::assertStringContainsString('Invalid authenticator code.', $response->body);
        self::assertSame(AuthSessionState::MfaPending, $session->state());
    }

    public function testMarksFullyAuthenticatedAndRotatesSessionAfterValidTotpCode(): void
    {
        $storage = [];
        $rotated = false;
        $pdo = $this->createMigratedConnection();
        $user = (new UserRepository($pdo))->create('user@example.com', 'password-hash');
        $credentials = new UserTotpCredentialRepository($pdo);
        $secretProtector = new TotpSecretProtector(str_repeat('a', 32), 'local');
        $secret = $this->activateTotp($credentials, $secretProtector, $user->id, $user->email);
        $session = new AuthSession($storage);
        $session->markMfaPending($user->id, $user->email);
        $csrf = new CsrfTokenManager($storage);
        $controller = new TotpChallengeController(
            $session,
            $csrf,
            new TotpLoginVerificationService($credentials, $secretProtector),
            static function () use (&$rotated): void {
                $rotated = true;
            },
        );
        $token = $csrf->issue('totp_challenge_form');
        $code = (new TotpGenerator())->generate($secret, time());

        $response = $controller->submit([
            'csrf_token' => $token->value,
            'code' => $code,
        ]);

        self::assertSame(303, $response->statusCode);
        self::assertSame(['Location' => '/account'], $response->headers);
        self::assertSame(AuthSessionState::FullyAuthenticated, $session->state());
        self::assertSame($user->id, $session->userId());
        self::assertSame($user->email, $session->userEmail());
        self::assertTrue($rotated);
    }

    private function verificationService(): TotpLoginVerificationService
    {
        return new TotpLoginVerificationService(
            new UserTotpCredentialRepository($this->createMigratedConnection()),
            new TotpSecretProtector(str_repeat('a', 32), 'local'),
        );
    }

    private function activateTotp(
        UserTotpCredentialRepository $credentials,
        TotpSecretProtector $secretProtector,
        int $userId,
        string $email,
    ): TotpSecret {
        $enrollment = new TotpEnrollmentService($credentials, $secretProtector);
        $pending = $enrollment->start($userId, $email);
        $secret = TotpSecret::fromBase32($pending->secretBase32);
        $code = (new TotpGenerator())->generate($secret, 59);

        self::assertTrue($enrollment->confirm($userId, $code, 59));

        return $secret;
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
}
