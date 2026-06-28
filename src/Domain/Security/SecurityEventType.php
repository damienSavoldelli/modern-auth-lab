<?php

declare(strict_types=1);

namespace ModernAuthLab\Domain\Security;

// Security events are part of the audit vocabulary. Keep them explicit so new
// authentication flows cannot invent ad hoc event names in controllers.
enum SecurityEventType: string
{
    case PasswordLoginSucceeded = 'password_login_succeeded';
    case PasswordLoginFailed = 'password_login_failed';
    case LogoutSucceeded = 'logout_succeeded';
    case LogoutCsrfFailed = 'logout_csrf_failed';
}
