<?php

declare(strict_types=1);

namespace ModernAuthLab\Session;

use InvalidArgumentException;

final readonly class SessionCookieOptions
{
    private const SAME_SITE_VALUES = ['Lax', 'Strict', 'None'];

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

    public static function forRequest(bool $isHttps): self
    {
        return new self(secure: $isHttps);
    }

    /**
     * @return array{lifetime: int, path: string, domain: string, secure: bool, httponly: bool, samesite: string}
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
