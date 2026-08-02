<?php

declare(strict_types=1);

namespace ModernAuthLab\Security\WebAuthn;

use ModernAuthLab\Domain\User\User;
use Symfony\Component\Serializer\Normalizer\DenormalizerInterface;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * WebAuthn attestation verifier backed by `web-auth/webauthn-lib`.
 *
 * This class is the narrow integration boundary with the third-party library.
 * Application services should depend on PasskeyAttestationVerifier instead.
 */
final readonly class WebAuthnLibPasskeyAttestationVerifier implements PasskeyAttestationVerifier
{
    /**
     * @param WebAuthnConfig $config Server-side relying-party configuration.
     */
    public function __construct(
        private WebAuthnConfig $config,
    ) {}

    /**
     * @param User $user Existing user enrolling a Passkey.
     * @param string $challenge Base64URL challenge previously issued by the server.
     * @param array<string, mixed> $credential Browser credential response payload.
     *
     * @return VerifiedPasskeyCredential Verified credential material.
     */
    public function verify(User $user, string $challenge, array $credential): VerifiedPasskeyCredential
    {
        $publicKeyCredential = $this->denormalizeCredential($credential);
        $response = $publicKeyCredential->response;

        if (! $response instanceof AuthenticatorAttestationResponse) {
            throw new \InvalidArgumentException('WebAuthn enrollment requires an attestation response.');
        }

        $record = $this->validator()->check(
            $response,
            $this->creationOptions($user, $challenge),
            $this->config->rpId,
        );

        return new VerifiedPasskeyCredential(
            Base64Url::encode($record->publicKeyCredentialId),
            Base64Url::encode($record->credentialPublicKey),
            $record->counter,
            $record->transports,
            $record->attestationType,
            $record->aaguid->toRfc4122(),
        );
    }

    /**
     * @param array<string, mixed> $credential Browser credential response payload.
     */
    private function denormalizeCredential(array $credential): PublicKeyCredential
    {
        $manager = AttestationStatementSupportManager::create();
        $serializer = (new WebauthnSerializerFactory($manager))->create();

        if (! $serializer instanceof DenormalizerInterface) {
            throw new \RuntimeException('WebAuthn serializer must support denormalization.');
        }

        $publicKeyCredential = $serializer->denormalize($credential, PublicKeyCredential::class, 'json');

        if (! $publicKeyCredential instanceof PublicKeyCredential) {
            throw new \InvalidArgumentException('Browser response could not be decoded as a public-key credential.');
        }

        return $publicKeyCredential;
    }

    private function validator(): AuthenticatorAttestationResponseValidator
    {
        $factory = new CeremonyStepManagerFactory();
        $factory->setAllowedOrigins($this->config->allowedOrigins);

        return AuthenticatorAttestationResponseValidator::create($factory->creationCeremony());
    }

    private function creationOptions(User $user, string $challenge): PublicKeyCredentialCreationOptions
    {
        return PublicKeyCredentialCreationOptions::create(
            PublicKeyCredentialRpEntity::create($this->config->rpName, $this->config->rpId),
            PublicKeyCredentialUserEntity::create(
                $user->email,
                Base64Url::encode(sprintf('user:%d', $user->id)),
                $user->email,
            ),
            $challenge,
            [
                PublicKeyCredentialParameters::createPk(-7),
                PublicKeyCredentialParameters::createPk(-257),
            ],
            AuthenticatorSelectionCriteria::create(
                userVerification: $this->config->userVerification,
                residentKey: AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_PREFERRED,
            ),
            PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
            timeout: $this->config->timeoutMs,
            hints: ['client-device', 'security-key', 'hybrid'],
        );
    }
}
