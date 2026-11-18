<?php
declare(strict_types=1);

namespace Light\Auth;

enum RateLimitScope: string
{
    case UsernameIp = 'username_ip';
    case Ip = 'ip';
}
