<?php

declare(strict_types=1);

namespace ModernAuthLab\Http;

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

    public static function notFound(): self
    {
        return self::json(['error' => 'Not found'], 404);
    }

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
