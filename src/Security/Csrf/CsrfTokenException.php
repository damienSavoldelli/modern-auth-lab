<?php

declare(strict_types=1);

namespace ModernAuthLab\Security\Csrf;

use RuntimeException;

final class CsrfTokenException extends RuntimeException
{
    public static function missing(string $tokenId): self
    {
        return new self(sprintf('CSRF token "%s" is missing.', $tokenId));
    }

    public static function invalid(string $tokenId): self
    {
        return new self(sprintf('CSRF token "%s" is invalid.', $tokenId));
    }
}
