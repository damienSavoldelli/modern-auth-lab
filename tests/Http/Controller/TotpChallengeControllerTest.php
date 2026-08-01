<?php

declare(strict_types=1);

namespace ModernAuthLab\Tests\Http\Controller;

use ModernAuthLab\Application\Security\SecurityEventLogger;
use ModernAuthLab\Application\Totp\TotpEnrollmentService;
use ModernAuthLab\Application\Totp\TotpLoginVerificationService;
use ModernAuthLab\Domain\Security\SecurityEventType;
use ModernAuthLab\Http\Controller\TotpChallengeController;
use ModernAuthLab\Infrastructure\Persistence\MigrationRepository;
use ModernAuthLab\Infrastructure\Persistence\MigrationRunner;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateSecurityEventsTable;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateUsersTable;
use ModernAuthLab\Infrastructure\Persistence\Migrations\CreateUserTotpCredentialsTable;
use ModernAuthLab\Infrastructure\Persistence\SecurityEventRepository;
use ModernAuthLab\Infrastructure\Persistence\UserRepository;
use ModernAuthLab\Infrastructure\Persistence\UserTotpCredentialRepository;
use ModernAuthLab\Security\Csrf\CsrfTokenManager;
use ModernAuthLab\Security\Totp\TotpChallengeRateLimiter;
use ModernAuthLab\Security\Totp\TotpGenerator;
use ModernAuthLab\Security\Totp\TotpRateLimitConfig;
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
            $this->rateLimiter($storage),
            $this->securityEventLogger(),
            '127.0.0.1',
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
            $this->rateLimiter($storage),
            $this->securityEventLogger(),
            '127.0.0.1',
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
            $this->rateLimiter($storage),
            $this->securityEventLogger(),
            '127.0.0.1',
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
            $this->rateLimiter($storage),
            $this->securityEventLogger(),
            '127.0.0.1',
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
            $this->rateLimiter($storage),
            $this->securityEventLogger(),
            '127.0.0.1',
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
            $this->rateLimiter($storage),
            $this->securityEventLogger(),
            '127.0.0.1',
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
        $pdo = $this->createMigratedConnection();
        $user = (new UserRepository($pdo))->create('user@example.com', 'password-hash');
        $session = new AuthSession($storage);
        $session->markMfaPending($user->id, $user->email);
        $csrf = new CsrfTokenManager($storage);
        $controller = new TotpChallengeController(
            $session,
            $csrf,
            $this->verificationService(),
            $this->rateLimiter($storage),
            new SecurityEventLogger(new SecurityEventRepository($pdo)),
            '127.0.0.1',
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

    public function testRecordsSecurityEventAfterInvalidTotpCode(): void
    {
        $storage = [];
        $pdo = $this->createMigratedConnection();
        $user = (new UserRepository($pdo))->create('user@example.com', 'password-hash');
        $events = new SecurityEventRepository($pdo);
        $session = new AuthSession($storage);
        $session->markMfaPending($user->id, 'USER@example.COM');
        $csrf = new CsrfTokenManager($storage);
        $controller = new TotpChallengeController(
            $session,
            $csrf,
            $this->verificationService(),
            $this->rateLimiter($storage),
            new SecurityEventLogger($events),
            '127.0.0.1',
            static function (): void {},
        );
        $token = $csrf->issue('totp_challenge_form');

        $controller->submit([
            'csrf_token' => $token->value,
            'code' => '123456',
        ]);

        self::assertSame(SecurityEventType::TotpChallengeFailed->value, $events->all()[0]['type']);
        self::assertSame($user->id, $events->all()[0]['user_id']);
        self::assertSame('user@example.com', $events->all()[0]['email']);
        self::assertSame('127.0.0.1', $events->all()[0]['client_ip']);
        self::assertStringNotContainsString('123456', json_encode($events->all(), JSON_THROW_ON_ERROR));
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
            $this->rateLimiter($storage),
            new SecurityEventLogger(new SecurityEventRepository($pdo)),
            '127.0.0.1',
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

    public function testRateLimitsRepeatedInvalidTotpCodes(): void
    {
        $storage = [];
        $pdo = $this->createMigratedConnection();
        $user = (new UserRepository($pdo))->create('user@example.com', 'password-hash');
        $session = new AuthSession($storage);
        $session->markMfaPending($user->id, $user->email);
        $csrf = new CsrfTokenManager($storage);
        $controller = new TotpChallengeController(
            $session,
            $csrf,
            $this->verificationService(),
            $this->rateLimiter($storage, maxAttempts: 2),
            new SecurityEventLogger(new SecurityEventRepository($pdo)),
            '127.0.0.1',
            static function (): void {},
        );

        for ($attempt = 0; $attempt < 2; $attempt++) {
            $token = $csrf->issue('totp_challenge_form');
            $controller->submit([
                'csrf_token' => $token->value,
                'code' => '123456',
            ]);
        }

        $token = $csrf->issue('totp_challenge_form');
        $response = $controller->submit([
            'csrf_token' => $token->value,
            'code' => '123456',
        ]);

        self::assertSame(429, $response->statusCode);
        self::assertStringContainsString('Too many attempts. Try again later.', $response->body);
        self::assertSame(AuthSessionState::MfaPending, $session->state());
    }

    public function testRecordsSecurityEventWhenTotpChallengeIsRateLimited(): void
    {
        $storage = [];
        $pdo = $this->createMigratedConnection();
        $user = (new UserRepository($pdo))->create('user@example.com', 'password-hash');
        $events = new SecurityEventRepository($pdo);
        $session = new AuthSession($storage);
        $session->markMfaPending($user->id, $user->email);
        $csrf = new CsrfTokenManager($storage);
        $controller = new TotpChallengeController(
            $session,
            $csrf,
            $this->verificationService(),
            $this->rateLimiter($storage, maxAttempts: 1),
            new SecurityEventLogger($events),
            '127.0.0.1',
            static function (): void {},
        );
        $firstToken = $csrf->issue('totp_challenge_form');
        $controller->submit([
            'csrf_token' => $firstToken->value,
            'code' => '123456',
        ]);
        $secondToken = $csrf->issue('totp_challenge_form');

        $controller->submit([
            'csrf_token' => $secondToken->value,
            'code' => '123456',
        ]);

        self::assertSame(SecurityEventType::TotpChallengeFailed->value, $events->all()[0]['type']);
        self::assertSame(SecurityEventType::TotpChallengeRateLimited->value, $events->all()[1]['type']);
    }

    public function testClearsTotpRateLimitAfterSuccessfulChallenge(): void
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
            $this->rateLimiter($storage, maxAttempts: 2),
            new SecurityEventLogger(new SecurityEventRepository($pdo)),
            '127.0.0.1',
            static function () use (&$rotated): void {
                $rotated = true;
            },
        );
        $firstInvalidToken = $csrf->issue('totp_challenge_form');
        $controller->submit([
            'csrf_token' => $firstInvalidToken->value,
            'code' => '123456',
        ]);
        $validToken = $csrf->issue('totp_challenge_form');
        $validCode = (new TotpGenerator())->generate($secret, time());

        $response = $controller->submit([
            'csrf_token' => $validToken->value,
            'code' => $validCode,
        ]);

        self::assertSame(303, $response->statusCode);
        self::assertSame(['Location' => '/account'], $response->headers);
        self::assertTrue($rotated);
        self::assertTrue($this->rateLimiter($storage, maxAttempts: 2)->isAllowed($this->rateLimitIdentifier($user->id)));
    }

    public function testRecordsSecurityEventAfterSuccessfulTotpCode(): void
    {
        $storage = [];
        $pdo = $this->createMigratedConnection();
        $events = new SecurityEventRepository($pdo);
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
            $this->rateLimiter($storage),
            new SecurityEventLogger($events),
            '127.0.0.1',
            static function (): void {},
        );
        $token = $csrf->issue('totp_challenge_form');
        $code = (new TotpGenerator())->generate($secret, time());

        $controller->submit([
            'csrf_token' => $token->value,
            'code' => $code,
        ]);

        self::assertSame(SecurityEventType::TotpChallengeSucceeded->value, $events->all()[0]['type']);
        self::assertSame($user->id, $events->all()[0]['user_id']);
        self::assertSame($user->email, $events->all()[0]['email']);
        self::assertStringNotContainsString($code, json_encode($events->all(), JSON_THROW_ON_ERROR));
    }

    private function verificationService(): TotpLoginVerificationService
    {
        return new TotpLoginVerificationService(
            new UserTotpCredentialRepository($this->createMigratedConnection()),
            new TotpSecretProtector(str_repeat('a', 32), 'local'),
        );
    }

    private function securityEventLogger(): SecurityEventLogger
    {
        return new SecurityEventLogger(new SecurityEventRepository($this->createMigratedConnection()));
    }

    /**
     * @param array<string, mixed> $storage
     */
    private function rateLimiter(array &$storage, int $maxAttempts = 5, int $lockSeconds = 300): TotpChallengeRateLimiter
    {
        return new TotpChallengeRateLimiter(
            $storage,
            TotpRateLimitConfig::fromEnvironment([
                'TOTP_RATE_LIMIT_MAX_ATTEMPTS' => (string) $maxAttempts,
                'TOTP_RATE_LIMIT_LOCK_SECONDS' => (string) $lockSeconds,
            ]),
        );
    }

    private function rateLimitIdentifier(int $userId): string
    {
        return hash('sha256', $userId . '|127.0.0.1');
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
            new CreateSecurityEventsTable(),
            new CreateUserTotpCredentialsTable(),
        ]);
        $runner->run();

        return $pdo;
    }
}
