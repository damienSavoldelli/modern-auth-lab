<?php

declare(strict_types=1);

namespace ModernAuthLab\Application\WebAuthn;

use ModernAuthLab\Infrastructure\Persistence\UserPasskeyCredentialRepository;

/**
 * Revokes one Passkey credential owned by a specific user.
 *
 * The service enforces ownership before delegating the actual persistence write
 * to the repository. Callers must have already established that the user is
 * fully authenticated: this service only guards the credential-to-user link.
 */
final readonly class PasskeyRevocationService
{
    /**
     * @param UserPasskeyCredentialRepository $credentials Passkey credential persistence.
     */
    public function __construct(
        private UserPasskeyCredentialRepository $credentials,
    ) {}

    /**
     * Revoke a Passkey credential owned by the given user.
     *
     * @param int $userId Fully authenticated user requesting revocation.
     * @param int $credentialId Persistence identifier of the Passkey to revoke.
     *
     * @throws \RuntimeException When the credential does not exist or belongs to another user.
     */
    public function revoke(int $userId, int $credentialId): void
    {
        $credential = $this->findOwnedCredential($userId, $credentialId);

        if ($credential === null) {
            throw new \RuntimeException('Passkey credential was not found for the requesting user.');
        }

        $this->credentials->revoke($credential->id);
    }

    private function findOwnedCredential(
        int $userId,
        int $credentialId,
    ): ?\ModernAuthLab\Infrastructure\Persistence\UserPasskeyCredential {
        foreach ($this->credentials->findActiveByUserId($userId) as $credential) {
            if ($credential->id === $credentialId) {
                return $credential;
            }
        }

        return null;
    }
}
