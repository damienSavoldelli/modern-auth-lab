<?php

declare(strict_types=1);

namespace ModernAuthLab\Http;

use Closure;

/**
 * Minimal method/path router for the PHP front controller.
 *
 * The router intentionally has no middleware system yet. Security boundaries
 * remain explicit in controllers until the repeated patterns justify extracting
 * shared middleware.
 */
final class Router
{
    /**
     * @var array<string, array<string, Closure(): Response>>
     */
    private array $routes = [];

    /**
     * Register a GET route.
     *
     * @param string $path Route path.
     * @param Closure(): Response $handler
     */
    public function get(string $path, Closure $handler): void
    {
        $this->routes['GET'][$this->normalizePath($path)] = $handler;
    }

    /**
     * Register a POST route.
     *
     * @param string $path Route path.
     * @param Closure(): Response $handler
     */
    public function post(string $path, Closure $handler): void
    {
        $this->routes['POST'][$this->normalizePath($path)] = $handler;
    }

    /**
     * Dispatch the request to a registered handler or return 404.
     *
     * @param string $method HTTP method.
     * @param string $path Request path.
     *
     * @return Response Matched route response or not-found response.
     */
    public function dispatch(string $method, string $path): Response
    {
        $normalizedMethod = strtoupper($method);
        $normalizedPath = $this->normalizePath($path);
        $handler = $this->routes[$normalizedMethod][$normalizedPath] ?? null;

        if ($handler === null) {
            return Response::notFound();
        }

        return $handler();
    }

    private function normalizePath(string $path): string
    {
        if ($path === '') {
            return '/';
        }

        if ($path !== '/' && str_ends_with($path, '/')) {
            return rtrim($path, '/');
        }

        return $path;
    }
}
