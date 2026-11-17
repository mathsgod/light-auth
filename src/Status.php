<?php
declare(strict_types=1);
namespace Light\Auth;
enum Status: string
{
    case Authenticated = 'authenticated';
    case InvalidCredentials = 'invalid_credentials';
    case Locked = 'locked';
    case PasswordExpired = 'password_expired';
    case SecondFactorRequired = 'second_factor_required';
}
