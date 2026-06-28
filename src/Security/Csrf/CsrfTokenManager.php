<?php

declare(strict_types=1);

namespace ModernAuthLab\Security\Csrf;

/**
 * Session-backed CSRF token manager.
 *
 * Tokens are bound to explicit token ids so each form/action can maintain its
 * own token slot. Validation uses hash_equals to avoid timing-safe comparison
 * mistakes in security-sensitive code.
 */
final class CsrfTokenManager
{
    private const STORAGE_KEY = '_csrf_tokens';
    private const TOKEN_BYTES = 32;

    /**
     * @param array<string, mixed> $storage Session-backed token storage.
     */
    public function __construct(
        private array &$storage,
    ) {}

    /**
     * Issue a fresh token for the given form/action identifier.
     *
     * @param string $tokenId Token slot identifier.
     *
     * @return CsrfToken Newly issued token.
     *
     * @throws CsrfTokenException When the token id is empty.
     * @throws \Random\RandomException When secure random generation fails.
     */
    public function issue(string $tokenId): CsrfToken
    {
        $this->assertValidTokenId($tokenId);

        $value = bin2hex(random_bytes(self::TOKEN_BYTES));
        $this->tokens()[$tokenId] = $value;

        return new CsrfToken($tokenId, $value);
    }

    /**
     * Validate a submitted token without consuming it.
     *
     * @param string $tokenId Token slot identifier.
     * @param string|null $submittedValue Submitted token value.
     *
     * @return void
     *
     * @throws CsrfTokenException When the token is missing or invalid.
     */
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

    /**
     * Validate and then remove the token to model one-time unsafe actions.
     *
     * @param string $tokenId Token slot identifier.
     * @param string|null $submittedValue Submitted token value.
     *
     * @return void
     *
     * @throws CsrfTokenException When the token is missing or invalid.
     */
    public function consume(string $tokenId, ?string $submittedValue): void
    {
        $this->validate($tokenId, $submittedValue);

        unset($this->tokens()[$tokenId]);
    }

    /**
     * Remove all CSRF tokens from the backing storage.
     *
     * @return void
     */
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
     * @return array<string, string> Token storage indexed by token id.
     */
    private function &tokens(): array
    {
        if (! isset($this->storage[self::STORAGE_KEY]) || ! is_array($this->storage[self::STORAGE_KEY])) {
            $this->storage[self::STORAGE_KEY] = [];
        }

        return $this->storage[self::STORAGE_KEY];
    }
}
