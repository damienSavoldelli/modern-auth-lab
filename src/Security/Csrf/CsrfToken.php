<?php

declare(strict_types=1);

namespace ModernAuthLab\Security\Csrf;

final readonly class CsrfToken
{
    public function __construct(
        public string $id,
        public string $value,
    ) {}
}
