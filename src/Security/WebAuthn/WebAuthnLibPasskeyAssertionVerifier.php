<?php

declare(strict_types=1);

namespace ModernAuthLab\Security\WebAuthn;

use ModernAuthLab\Infrastructure\Persistence\UserPasskeyCredential;
use Symfony\Component\Serializer\Normalizer\DenormalizerInterface;
use Symfony\Component\Uid\Uuid;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\CredentialRecord;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\TrustPath\EmptyTrustPath;

/**
 * WebAuthn assertion verifier backed by `web-auth/webauthn-lib`.
 *
 * This class is the narrow integration boundary with the third-party library
 * for authentication ceremonies. Application services should depend on
 * PasskeyAssertionVerifier instead.
 */
final readonly class WebAuthnLibPasskeyAssertionVerifier implements PasskeyAssertionVerifier
{
    /**
     * @param WebAuthnConfig $config Server-side relying-party configuration.
     */
    public function __construct(
        private WebAuthnConfig $config,
    ) {}

    /**
     * @param UserPasskeyCredential $credential Stored credential matching the browser response.
     * @param string $challenge Base64URL challenge previously issued by the server.
     * @param array<string, mixed> $assertion Browser assertion payload.
     *
     * @return VerifiedPasskeyAssertion Verified assertion with the updated sign counter.
     */
    public function verify(
        UserPasskeyCredential $credential,
        string $challenge,
        array $assertion,
    ): VerifiedPasskeyAssertion {
        $publicKeyCredential = $this->denormalizeCredential($assertion);
        $response = $publicKeyCredential->response;

        if (! $response instanceof AuthenticatorAssertionResponse) {
            throw new \InvalidArgumentException('WebAuthn authentication requires an assertion response.');
        }

        $credentialRecord = $this->credentialRecord($credential);
        $updated = $this->validator()->check(
            $credentialRecord,
            $response,
            $this->requestOptions($credential, $challenge),
            $this->config->rpId,
            null,
        );

        return new VerifiedPasskeyAssertion(
            Base64Url::encode($updated->publicKeyCredentialId),
            $updated->counter,
        );
    }

    /**
     * @param array<string, mixed> $assertion Browser assertion payload.
     */
    private function denormalizeCredential(array $assertion): PublicKeyCredential
    {
        $manager = AttestationStatementSupportManager::create();
        $serializer = (new WebauthnSerializerFactory($manager))->create();

        if (! $serializer instanceof DenormalizerInterface) {
            throw new \RuntimeException('WebAuthn serializer must support denormalization.');
        }

        $publicKeyCredential = $serializer->denormalize($assertion, PublicKeyCredential::class, 'json');

        if (! $publicKeyCredential instanceof PublicKeyCredential) {
            throw new \InvalidArgumentException('Browser response could not be decoded as a public-key credential.');
        }

        return $publicKeyCredential;
    }

    private function validator(): AuthenticatorAssertionResponseValidator
    {
        $factory = new CeremonyStepManagerFactory();
        $factory->setAllowedOrigins($this->config->allowedOrigins);

        return AuthenticatorAssertionResponseValidator::create($factory->requestCeremony());
    }

    private function requestOptions(
        UserPasskeyCredential $credential,
        string $challenge,
    ): PublicKeyCredentialRequestOptions {
        return PublicKeyCredentialRequestOptions::create(
            $challenge,
            $this->config->rpId,
            [
                PublicKeyCredentialDescriptor::create(
                    'public-key',
                    Base64Url::decode($credential->credentialId),
                    $credential->transports,
                ),
            ],
            $this->config->userVerification,
            $this->config->timeoutMs,
        );
    }

    private function credentialRecord(UserPasskeyCredential $credential): CredentialRecord
    {
        return new CredentialRecord(
            Base64Url::decode($credential->credentialId),
            'public-key',
            $credential->transports,
            $credential->attestationType ?? 'none',
            new EmptyTrustPath(),
            Uuid::fromString($credential->aaguid ?? '00000000-0000-0000-0000-000000000000'),
            Base64Url::decode($credential->publicKey),
            sprintf('user:%d', $credential->userId),
            $credential->signCount,
        );
    }
}
