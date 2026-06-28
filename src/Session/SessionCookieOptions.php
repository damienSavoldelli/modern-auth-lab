<?php

declare(strict_types=1);

namespace ModernAuthLab\Session;

use InvalidArgumentException;

/**
 * Validated PHP session cookie options.
 *
 * Defaults favor secure cookies. Local HTTP development can disable Secure via
 * forRequest(false), while SameSite=None remains forbidden without Secure.
 */
final readonly class SessionCookieOptions
{
    private const SAME_SITE_VALUES = ['Lax', 'Strict', 'None'];

    /**
     * Validate cookie policy before it is passed to PHP's session layer.
     *
     * @param string $name Session cookie name.
     * @param int $lifetime Cookie lifetime in seconds.
     * @param string $path Cookie path.
     * @param string $domain Cookie domain.
     * @param bool $secure Whether the cookie requires HTTPS.
     * @param bool $httpOnly Whether JavaScript access is blocked.
     * @param string $sameSite SameSite policy: Lax, Strict, or None.
     *
     * @throws InvalidArgumentException When cookie policy is invalid.
     */
    public function __construct(
        public string $name = 'modern_auth_lab_session',
        public int $lifetime = 0,
        public string $path = '/',
        public string $domain = '',
        public bool $secure = true,
        public bool $httpOnly = true,
        public string $sameSite = 'Lax',
    ) {
        if ($this->name === '') {
            throw new InvalidArgumentException('Session cookie name cannot be empty.');
        }

        if ($this->lifetime < 0) {
            throw new InvalidArgumentException('Session cookie lifetime cannot be negative.');
        }

        if (! in_array($this->sameSite, self::SAME_SITE_VALUES, true)) {
            throw new InvalidArgumentException('Session cookie SameSite must be Lax, Strict, or None.');
        }

        if ($this->sameSite === 'None' && ! $this->secure) {
            throw new InvalidArgumentException('Session cookie SameSite=None requires Secure.');
        }
    }

    /**
     * Build cookie options for the current request scheme.
     *
     * @param bool $isHttps True when the current request is HTTPS.
     *
     * @return self Cookie options adapted to the request scheme.
     */
    public static function forRequest(bool $isHttps): self
    {
        return new self(secure: $isHttps);
    }

    /**
     * Convert options to the array shape expected by session_set_cookie_params.
     *
     * @return array{lifetime: int, path: string, domain: string, secure: bool, httponly: bool, samesite: string} PHP session cookie parameters.
     */
    public function toPhpCookieParams(): array
    {
        return [
            'lifetime' => $this->lifetime,
            'path' => $this->path,
            'domain' => $this->domain,
            'secure' => $this->secure,
            'httponly' => $this->httpOnly,
            'samesite' => $this->sameSite,
        ];
    }
}
