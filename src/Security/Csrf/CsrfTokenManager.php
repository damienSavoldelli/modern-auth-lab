<?php

declare(strict_types=1);

namespace ModernAuthLab\Security\Csrf;

final class CsrfTokenManager
{
    private const STORAGE_KEY = '_csrf_tokens';
    private const TOKEN_BYTES = 32;

    /**
     * @param array<string, mixed> $storage
     */
    public function __construct(
        private array &$storage,
    ) {}

    public function issue(string $tokenId): CsrfToken
    {
        $this->assertValidTokenId($tokenId);

        $value = bin2hex(random_bytes(self::TOKEN_BYTES));
        $this->tokens()[$tokenId] = $value;

        return new CsrfToken($tokenId, $value);
    }

    public function validate(string $tokenId, ?string $submittedValue): void
    {
        $this->assertValidTokenId($tokenId);

        $expectedValue = $this->tokens()[$tokenId] ?? null;

        if (! is_string($expectedValue) || $submittedValue === null || $submittedValue === '') {
            throw CsrfTokenException::missing($tokenId);
        }

        if (! hash_equals($expectedValue, $submittedValue)) {
            throw CsrfTokenException::invalid($tokenId);
        }
    }

    public function consume(string $tokenId, ?string $submittedValue): void
    {
        $this->validate($tokenId, $submittedValue);

        unset($this->tokens()[$tokenId]);
    }

    public function clear(): void
    {
        unset($this->storage[self::STORAGE_KEY]);
    }

    private function assertValidTokenId(string $tokenId): void
    {
        if ($tokenId === '') {
            throw new CsrfTokenException('CSRF token id cannot be empty.');
        }
    }

    /**
     * @return array<string, string>
     */
    private function &tokens(): array
    {
        if (! isset($this->storage[self::STORAGE_KEY]) || ! is_array($this->storage[self::STORAGE_KEY])) {
            $this->storage[self::STORAGE_KEY] = [];
        }

        return $this->storage[self::STORAGE_KEY];
    }
}
