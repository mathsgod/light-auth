<?php
declare(strict_types=1);

namespace Light\Auth\Tests;

use Light\Auth\{AttemptLimiter, LoginService, Policy, RateLimitScope, Status};
use Light\Auth\WebAuthn\WebAuthnService;
use OTPHP\TOTP;

final class RateLimitScopeTest extends AuthTestCase
{
    private function useScope(RateLimitScope $scope): void
    {
        $this->limiter = new AttemptLimiter($this->state, new Policy(3, 60, 30, $scope), $this->clock);
        $this->login = new LoginService($this->users, $this->limiter, $this->challenges, $this->totp, $this->clock);
    }

    public function testDefaultScopeKeepsLegacyKeysAndUsernameIsolation(): void
    {
        self::assertSame(RateLimitScope::UsernameIp, (new Policy())->scope);
        self::assertSame(AttemptLimiter::key('alice', 'ip'), $this->limiter->loginKey(' ALICE ', 'ip'));
        for ($i = 0; $i < 3; $i++) $this->login->password('missing', 'wrong', 'ip', 'browser');
        self::assertSame(Status::Locked, $this->login->password('missing', 'wrong', 'ip', 'browser')->status);
        self::assertSame(Status::InvalidCredentials, $this->login->password('other', 'wrong', 'ip', 'browser')->status);
    }

    public function testIpScopeAggregatesKnownAndUnknownUsernamesButSeparatesIps(): void
    {
        $this->useScope(RateLimitScope::Ip);
        $this->addUser();
        foreach (['alice', 'missing', 'different'] as $name) {
            self::assertSame(Status::InvalidCredentials, $this->login->password($name, 'wrong', 'one', 'browser')->status);
        }
        self::assertSame(Status::Locked, $this->login->password('alice', 'correct', 'one', 'browser')->status);
        self::assertSame(Status::Locked, $this->login->password('another', 'wrong', 'one', 'browser')->status);
        self::assertSame(Status::Authenticated, $this->login->password('alice', 'correct', 'two', 'browser')->status);
    }

    public function testSuccessfulPasswordLoginCannotResetAnIpQuota(): void
    {
        $this->useScope(RateLimitScope::Ip);
        $this->addUser();
        $this->login->password('missing', 'wrong', 'ip', 'browser');
        self::assertSame(Status::Authenticated, $this->login->password('alice', 'correct', 'ip', 'browser')->status);
        self::assertSame(Status::Authenticated, $this->login->password('alice', 'correct', 'ip', 'browser')->status);
        self::assertSame(Status::Locked, $this->login->password('missing', 'wrong', 'ip', 'browser')->status);
    }

    public function testSuccessfulSecondFactorCannotResetAnIpQuota(): void
    {
        $this->useScope(RateLimitScope::Ip);
        $user = $this->addUser(mfa: true);
        $this->login->password('missing', 'wrong', 'ip', 'browser');
        $pending = $this->login->password('alice', 'correct', 'ip', 'browser');
        self::assertSame(Status::SecondFactorRequired, $pending->status);
        $code = TOTP::createFromSecret($user->totpSecret)->at($this->clock->timestamp);
        self::assertSame(Status::Authenticated, $this->login->secondFactor($pending->challengeToken, $code, 'ip', 'browser')->status);
        $this->login->password('missing', 'wrong', 'ip', 'browser');
        self::assertSame(Status::Locked, $this->login->password('different', 'wrong', 'ip', 'browser')->status);
    }

    public function testIpWindowExpiresWithoutExtensionByBlockedRequests(): void
    {
        $this->useScope(RateLimitScope::Ip);
        foreach (['one', 'two', 'three'] as $name) $this->login->password($name, 'wrong', 'ip', 'browser');
        $this->clock->timestamp += 59;
        self::assertSame(1, $this->login->password('four', 'wrong', 'ip', 'browser')->retryAfter);
        $this->clock->timestamp++;
        self::assertSame(Status::InvalidCredentials, $this->login->password('five', 'wrong', 'ip', 'browser')->status);
    }

    public function testSwitchingScopesDoesNotReuseTheOtherScopesKeys(): void
    {
        for ($i = 0; $i < 3; $i++) $this->login->password('alice', 'wrong', 'ip', 'browser');
        $this->useScope(RateLimitScope::Ip);
        self::assertSame(Status::InvalidCredentials, $this->login->password('alice', 'wrong', 'ip', 'browser')->status);
        $this->useScope(RateLimitScope::UsernameIp);
        self::assertSame(Status::Locked, $this->login->password('alice', 'wrong', 'ip', 'browser')->status);
    }

    public function testPasswordAndPasskeySubmissionsShareTheIpQuota(): void
    {
        $this->useScope(RateLimitScope::Ip);
        $this->login->password('missing', 'wrong', 'ip', 'browser');
        $passkeys = new WebAuthnService($this->users, new MemoryCredentials(), $this->challenges, $this->limiter, 'example.test', ['https://example.test']);
        for ($i = 0; $i < 2; $i++) {
            $request = $passkeys->begin('browser');
            self::assertSame(Status::InvalidCredentials, $passkeys->complete($request->token, [], 'ip', 'browser')->status);
        }
        self::assertSame(Status::Locked, $this->login->password('other', 'wrong', 'ip', 'browser')->status);
        $request = $passkeys->begin('browser');
        self::assertSame(Status::Locked, $passkeys->complete($request->token, [], 'ip', 'browser')->status);
    }

    public function testSuccessfulPasskeyLoginCannotResetTheSharedIpQuota(): void
    {
        $this->useScope(RateLimitScope::Ip);
        $this->addUser();
        $credentials = new MemoryCredentials();
        $authenticator = new PasskeyAuthenticator();
        $enrollment = new \Light\Auth\WebAuthn\WebAuthnEnrollment($this->users, $credentials, $this->challenges, $this->limiter, 'example.test', 'Example', ['https://example.test']);
        $creation = $enrollment->begin('42', 'Alice', 'browser');
        $record = $enrollment->confirm('42', $creation->token, $authenticator->attestation($creation), 'browser');
        self::assertNotNull($record);
        $credentials->items[$record->id] = $record;

        $this->login->password('missing', 'wrong', 'ip', 'browser');
        $passkeys = new WebAuthnService($this->users, $credentials, $this->challenges, $this->limiter, 'example.test', ['https://example.test']);
        $request = $passkeys->begin('browser');
        self::assertSame(Status::Authenticated, $passkeys->complete($request->token, $authenticator->assertion($request, hash('sha256', '42', true)), 'ip', 'browser')->status);
        self::assertSame(Status::InvalidCredentials, $this->login->password('other', 'wrong', 'ip', 'browser')->status);
        self::assertSame(Status::Locked, $this->login->password('different', 'wrong', 'ip', 'browser')->status);
    }
}
