<?php

declare(strict_types=1);

namespace ModernAuthLab\Http\Controller;

use JsonException;
use ModernAuthLab\Application\Security\SecurityEventLogger;
use ModernAuthLab\Application\WebAuthn\PasskeyEnrollmentChallengeService;
use ModernAuthLab\Application\WebAuthn\PasskeyEnrollmentVerificationService;
use ModernAuthLab\Domain\Security\SecurityEventType;
use ModernAuthLab\Domain\User\User;
use ModernAuthLab\Http\Response;
use ModernAuthLab\Infrastructure\Persistence\UserRepository;
use ModernAuthLab\Security\WebAuthn\Base64Url;
use ModernAuthLab\Session\AuthSession;
use Throwable;

/**
 * Exposes Passkey enrollment ceremonies as JSON HTTP endpoints.
 *
 * The controller only orchestrates request framing and error handling. Challenge
 * generation, attestation verification, and credential persistence remain in the
 * application services.
 */
final readonly class PasskeyEnrollmentController
{
    /**
     * @param AuthSession $session Current authentication session facade.
     * @param UserRepository $users User persistence lookup.
     * @param PasskeyEnrollmentChallengeService $challengeService Enrollment challenge generator.
     * @param PasskeyEnrollmentVerificationService $verificationService Enrollment verification workflow.
     * @param SecurityEventLogger $securityEvents Audit logger for enrollment events.
     * @param string $clientIp Server-observed client IP.
     */
    public function __construct(
        private AuthSession $session,
        private UserRepository $users,
        private PasskeyEnrollmentChallengeService $challengeService,
        private PasskeyEnrollmentVerificationService $verificationService,
        private SecurityEventLogger $securityEvents,
        private string $clientIp,
    ) {}

    /**
     * Return the JSON-ready Passkey enrollment options for the current user.
     *
     * @return Response JSON `publicKey` creation options or generic failure.
     */
    public function challenge(): Response
    {
        $user = $this->currentUser();

        if ($user === null) {
            return Response::json(['error' => 'unauthorized'], 401);
        }

        try {
            $result = $this->challengeService->start($user);
        } catch (Throwable) {
            return Response::json(['error' => 'server_error'], 500);
        }

        return Response::json(['publicKey' => $result->publicKeyOptions]);
    }

    /**
     * Verify a browser enrollment response and store the Passkey credential.
     *
     * @param array<string, mixed> $body Decoded JSON request body.
     *
     * @return Response JSON success or generic verification failure.
     */
    public function verify(array $body): Response
    {
        $user = $this->currentUser();

        if ($user === null) {
            return Response::json(['error' => 'unauthorized'], 401);
        }

        $credential = $body['credential'] ?? null;
        $name = is_string($body['name'] ?? null) ? (string) $body['name'] : '';

        if (! is_array($credential)) {
            $this->securityEvents->record(
                SecurityEventType::PasskeyEnrollmentFailed,
                $user->id,
                $user->email,
                $this->clientIp,
            );

            return Response::json(['error' => 'invalid_payload'], 400);
        }

        $challenge = $this->extractChallenge($credential);

        if ($challenge === null) {
            $this->securityEvents->record(
                SecurityEventType::PasskeyEnrollmentFailed,
                $user->id,
                $user->email,
                $this->clientIp,
            );

            return Response::json(['error' => 'invalid_payload'], 400);
        }

        try {
            $this->verificationService->verify($user, $challenge, $credential, $name);
        } catch (Throwable) {
            $this->securityEvents->record(
                SecurityEventType::PasskeyEnrollmentFailed,
                $user->id,
                $user->email,
                $this->clientIp,
            );

            return Response::json(['error' => 'verification_failed'], 400);
        }

        $this->securityEvents->record(
            SecurityEventType::PasskeyEnrollmentSucceeded,
            $user->id,
            $user->email,
            $this->clientIp,
        );

        return Response::json(['status' => 'ok']);
    }

    /**
     * Resolve the current fully authenticated user, or null when the session
     * does not allow Passkey enrollment.
     */
    private function currentUser(): ?User
    {
        if (! $this->session->state()->isFullyAuthenticated()) {
            return null;
        }

        $userId = $this->session->userId();

        if ($userId === null) {
            return null;
        }

        return $this->users->findById($userId);
    }

    /**
     * Extract the Base64URL challenge from a WebAuthn browser response.
     *
     * The challenge sits inside `response.clientDataJSON`, itself a Base64URL
     * encoded JSON object with a `challenge` field. Extracting it here keeps
     * the verification service agnostic of transport framing.
     *
     * @param array<string, mixed> $credential Browser credential response payload.
     */
    private function extractChallenge(array $credential): ?string
    {
        $response = $credential['response'] ?? null;

        if (! is_array($response)) {
            return null;
        }

        $clientDataJson = $response['clientDataJSON'] ?? null;

        if (! is_string($clientDataJson) || $clientDataJson === '') {
            return null;
        }

        try {
            $decoded = Base64Url::decode($clientDataJson);
            /** @var array<string, mixed> $clientData */
            $clientData = json_decode($decoded, true, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException|\InvalidArgumentException) {
            return null;
        }

        $challenge = $clientData['challenge'] ?? null;

        return is_string($challenge) && $challenge !== '' ? $challenge : null;
    }
}
