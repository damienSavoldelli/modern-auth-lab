<?php

declare(strict_types=1);

namespace ModernAuthLab\Application\Auth;

use ModernAuthLab\Infrastructure\Persistence\UserRepository;
use ModernAuthLab\Security\Password\PasswordHasher;

/**
 * Coordinates user lookup and password-hash verification.
 *
 * This service does not decide session state, rate limiting, logging, or MFA
 * requirements. Those concerns stay in the HTTP/security orchestration layer so
 * password verification remains focused and easy to test.
 */
final readonly class PasswordAuthenticator
{
    /**
     * Receive the persistence and hashing collaborators required for password checks.
     *
     * @param UserRepository $users User lookup boundary.
     * @param PasswordHasher $passwords Password hashing and verification service.
     */
    public function __construct(
        private UserRepository $users,
        private PasswordHasher $passwords,
    ) {}

    /**
     * Verify submitted credentials and return a generic result.
     *
     * Missing users and invalid passwords both return failure so callers can
     * avoid account enumeration in user-facing responses.
     *
     * @param string $email Submitted email/account identifier.
     * @param string $plainPassword Submitted plain password.
     *
     * @return PasswordAuthenticationResult Generic success/failure result.
     */
    public function authenticate(string $email, string $plainPassword): PasswordAuthenticationResult
    {
        $user = $this->users->findByEmail($email);

        if ($user === null) {
            return PasswordAuthenticationResult::failure();
        }

        if (! $this->passwords->verify($plainPassword, $user->passwordHash)) {
            return PasswordAuthenticationResult::failure();
        }

        return PasswordAuthenticationResult::success($user);
    }
}
