<?php

declare(strict_types=1);

namespace ModernAuthLab\Http;

use Closure;

final class Router
{
    /**
     * @var array<string, array<string, Closure(): Response>>
     */
    private array $routes = [];

    /**
     * @param Closure(): Response $handler
     */
    public function get(string $path, Closure $handler): void
    {
        $this->routes['GET'][$this->normalizePath($path)] = $handler;
    }

    /**
     * @param Closure(): Response $handler
     */
    public function post(string $path, Closure $handler): void
    {
        $this->routes['POST'][$this->normalizePath($path)] = $handler;
    }

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
