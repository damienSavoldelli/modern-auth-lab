<?php

declare(strict_types=1);

namespace ModernAuthLab\Tests\Http;

use ModernAuthLab\Http\Response;
use ModernAuthLab\Http\Router;
use PHPUnit\Framework\TestCase;

final class RouterTest extends TestCase
{
    public function testDispatchesMatchingGetRoute(): void
    {
        $router = new Router();
        $router->get('/health', static fn(): Response => Response::json(['status' => 'ok']));

        $response = $router->dispatch('GET', '/health');

        self::assertSame(200, $response->statusCode);
        self::assertSame('{"status":"ok"}', $response->body);
    }

    public function testNormalizesTrailingSlash(): void
    {
        $router = new Router();
        $router->get('/health', static fn(): Response => Response::json(['status' => 'ok']));

        $response = $router->dispatch('GET', '/health/');

        self::assertSame(200, $response->statusCode);
    }

    public function testDispatchesMatchingPostRoute(): void
    {
        $router = new Router();
        $router->post('/login', static fn(): Response => Response::html('login posted'));

        $response = $router->dispatch('POST', '/login');

        self::assertSame(200, $response->statusCode);
        self::assertSame('login posted', $response->body);
    }

    public function testReturnsNotFoundForUnknownRoute(): void
    {
        $router = new Router();

        $response = $router->dispatch('GET', '/missing');

        self::assertSame(404, $response->statusCode);
        self::assertSame('{"error":"Not found"}', $response->body);
    }
}
