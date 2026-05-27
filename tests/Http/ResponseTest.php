<?php

declare(strict_types=1);

namespace ModernAuthLab\Tests\Http;

use ModernAuthLab\Http\Response;
use PHPUnit\Framework\TestCase;

final class ResponseTest extends TestCase
{
    public function testJsonResponseEncodesDataAndSetsContentType(): void
    {
        $response = Response::json(['status' => 'ok']);

        self::assertSame('{"status":"ok"}', $response->body);
        self::assertSame(200, $response->statusCode);
        self::assertSame(
            ['Content-Type' => 'application/json; charset=utf-8'],
            $response->headers,
        );
    }

    public function testNotFoundResponseUsesJsonBodyAnd404Status(): void
    {
        $response = Response::notFound();

        self::assertSame('{"error":"Not found"}', $response->body);
        self::assertSame(404, $response->statusCode);
    }
}
