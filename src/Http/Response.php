<?php

declare(strict_types=1);

namespace ModernAuthLab\Http;

/**
 * Small immutable HTTP response value object.
 *
 * The project keeps HTTP primitives explicit instead of introducing a framework
 * response stack at this stage.
 */
final readonly class Response
{
    /**
     * @param array<string, string> $headers
     */
    public function __construct(
        public string $body,
        public int $statusCode = 200,
        public array $headers = [],
    ) {}

    /**
     * Build a JSON response with a strict UTF-8 JSON content type.
     *
     * @param array<string, mixed> $data
     */
    public static function json(array $data, int $statusCode = 200): self
    {
        return new self(
            self::encodeJson($data),
            $statusCode,
            ['Content-Type' => 'application/json; charset=utf-8'],
        );
    }

    /**
     * Build the default not-found response.
     */
    public static function notFound(): self
    {
        return self::json(['error' => 'Not found'], 404);
    }

    /**
     * Build an HTML response.
     */
    public static function html(string $body, int $statusCode = 200): self
    {
        return new self(
            $body,
            $statusCode,
            ['Content-Type' => 'text/html; charset=utf-8'],
        );
    }

    /**
     * Build a redirect response using 303 by default for POST/redirect/GET.
     */
    public static function redirect(string $location, int $statusCode = 303): self
    {
        return new self(
            '',
            $statusCode,
            ['Location' => $location],
        );
    }

    /**
     * Emit the response through PHP's native HTTP output functions.
     */
    public function send(): void
    {
        http_response_code($this->statusCode);

        foreach ($this->headers as $name => $value) {
            header($name . ': ' . $value);
        }

        echo $this->body;
    }

    /**
     * @param array<string, mixed> $data
     */
    private static function encodeJson(array $data): string
    {
        return json_encode($data, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    }
}
