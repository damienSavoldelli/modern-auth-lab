<?php

declare(strict_types=1);

namespace ModernAuthLab\Application\Security;

use ModernAuthLab\Domain\Security\SecurityEventType;
use ModernAuthLab\Infrastructure\Persistence\SecurityEventRepository;

final readonly class SecurityEventLogger
{
    public function __construct(
        private SecurityEventRepository $events,
    ) {}

    public function record(
        SecurityEventType $type,
        ?int $userId,
        ?string $email,
        string $clientIp,
    ): void {
        $this->events->record(
            $type,
            $userId,
            $email === null ? null : strtolower(trim($email)),
            $clientIp,
        );
    }
}
