<?php

declare(strict_types=1);

namespace ModernAuthLab\Domain\Security;

enum SecurityEventType: string
{
    case PasswordLoginSucceeded = 'password_login_succeeded';
    case PasswordLoginFailed = 'password_login_failed';
    case LogoutSucceeded = 'logout_succeeded';
    case LogoutCsrfFailed = 'logout_csrf_failed';
}
