<?php

declare(strict_types=1);

namespace ModernAuthLab\Application\User;

use ModernAuthLab\Domain\User\User;

final readonly class DevUserSeedResult
{
    public function __construct(
        public bool $created,
        public User $user,
    ) {}
}
