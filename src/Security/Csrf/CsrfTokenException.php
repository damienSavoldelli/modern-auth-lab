<?php

declare(strict_types=1);

namespace ModernAuthLab\Security\Csrf;

use RuntimeException;

/**
 * Exception raised when CSRF validation cannot accept a submitted token.
 *
 * Messages are explicit for developers, but controllers still decide what is
 * safe to show to users.
 */
final class CsrfTokenException extends RuntimeException
{
    /**
     * Build an exception for absent or empty submitted token values.
     */
    public static function missing(string $tokenId): self
    {
        return new self(sprintf('CSRF token "%s" is missing.', $tokenId));
    }

    /**
     * Build an exception for submitted token values that do not match storage.
     */
    public static function invalid(string $tokenId): self
    {
        return new self(sprintf('CSRF token "%s" is invalid.', $tokenId));
    }
}
