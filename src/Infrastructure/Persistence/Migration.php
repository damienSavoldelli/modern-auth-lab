<?php

declare(strict_types=1);

namespace ModernAuthLab\Infrastructure\Persistence;

interface Migration
{
    public function version(): string;

    public function up(): string;
}
