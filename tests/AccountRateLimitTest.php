<?php
declare(strict_types=1);

namespace Light\Auth\Tests;

use Light\Auth\{AttemptLimiter, LoginService, Policy, RateLimitScope, Status};

final class AccountRateLimitTest extends AuthTestCase
{
    public function testFailedPasswordsShareAnAccountLimitAcrossIpsAndScopes(): void
    {
        $this->addUser();
        foreach (RateLimitScope::cases() as $scope) {
            $login = $this->loginWithAccountLimit($scope);
            foreach (['alice', 'missing'] as $name) {
                self::assertSame(Status::InvalidCredentials, $login->password($name, 'wrong', 'one', 'browser')->status);
                self::assertSame(Status::InvalidCredentials, $login->password(strtoupper($name), 'wrong', 'two', 'browser')->status);
                self::assertSame(Status::Locked, $login->password($name, 'correct', 'three', 'browser')->status);
            }
            self::assertSame(Status::InvalidCredentials, $login->password('other', 'wrong', 'three', 'browser')->status);
            $this->clock->timestamp += 60;
            self::assertSame(Status::Authenticated, $login->password('alice', 'correct', 'three', 'browser')->status);
        }
    }

    public function testFailedTotpAttemptsCountAcrossIps(): void
    {
        $this->addUser(mfa: true);
        $login = $this->loginWithAccountLimit(RateLimitScope::UsernameIp);
        foreach (['one', 'two'] as $ip) {
            $pending = $login->password('alice', 'correct', $ip, 'browser');
            self::assertSame(Status::SecondFactorRequired, $pending->status);
            self::assertSame(Status::InvalidCredentials, $login->secondFactor($pending->challengeToken, 'bad', $ip, 'browser')->status);
        }
        self::assertSame(Status::Locked, $login->password('alice', 'correct', 'three', 'browser')->status);
    }

    private function loginWithAccountLimit(RateLimitScope $scope): LoginService
    {
        $limiter = new AttemptLimiter($this->state, new Policy(3, 60, 30, $scope, accountMaxAttempts: 2), $this->clock);
        return new LoginService($this->users, $limiter, $this->challenges, $this->totp, $this->clock);
    }
}
