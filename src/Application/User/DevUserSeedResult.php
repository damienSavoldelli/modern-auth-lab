<?php

declare(strict_types=1);

namespace ModernAuthLab\Application\User;

use ModernAuthLab\Domain\User\User;

/**
 * Result object for the local development user seed command.
 *
 * The command is idempotent: it can either create the development account or
 * report that the same account already exists.
 */
final readonly class DevUserSeedResult
{
    /**
     * Describe whether the seed operation created or reused the user.
     *
     * @param bool $created True when the user was created by this run.
     * @param User $user Created or existing development user.
     */
    public function __construct(
        public bool $created,
        public User $user,
    ) {}
}
