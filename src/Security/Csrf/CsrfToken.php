<?php

declare(strict_types=1);

namespace ModernAuthLab\Security\Csrf;

/**
 * Immutable CSRF token issued for one named form or unsafe action.
 */
final readonly class CsrfToken
{
    /**
     * Carry the token id and generated value.
     */
    public function __construct(
        public string $id,
        public string $value,
    ) {}
}
