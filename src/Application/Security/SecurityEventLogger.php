<?php

declare(strict_types=1);

namespace ModernAuthLab\Application\Security;

use ModernAuthLab\Domain\Security\SecurityEventType;
use ModernAuthLab\Infrastructure\Persistence\SecurityEventRepository;

/**
 * Application-facing security event writer.
 *
 * Controllers use this service instead of writing directly to persistence so
 * normalization rules and future policy checks stay centralized.
 */
final readonly class SecurityEventLogger
{
    /**
     * Receive the event repository used for durable audit writes.
     *
     * @param SecurityEventRepository $events Durable security event storage.
     */
    public function __construct(
        private SecurityEventRepository $events,
    ) {}

    /**
     * Record an authentication-sensitive event without storing secrets.
     *
     * @param SecurityEventType $type Event vocabulary value.
     * @param int|null $userId Authenticated user id when known.
     * @param string|null $email Submitted or known email when relevant.
     * @param string $clientIp Server-observed client IP.
     */
    public function record(
        SecurityEventType $type,
        ?int $userId,
        ?string $email,
        string $clientIp,
    ): void {
        // Normalize at the application boundary so controllers do not duplicate
        // security-event hygiene rules before persistence.
        $this->events->record(
            $type,
            $userId,
            $email === null ? null : strtolower(trim($email)),
            $clientIp,
        );
    }
}
