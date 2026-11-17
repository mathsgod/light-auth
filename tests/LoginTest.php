<?php
declare(strict_types=1);
namespace Light\Auth\Tests;
use Light\Auth\{AttemptLimiter, Status, User};
use OTPHP\TOTP;
final class LoginTest extends AuthTestCase
{
    public function testPasswordSuccessOnlyExposesAuthenticatedUserId(): void
    {
        $this->addUser();
        $result = $this->login->password(' ALICE ', 'correct', '127.0.0.1', 'browser');
        self::assertSame(Status::Authenticated, $result->status);
        self::assertSame('42', $result->userId);
        self::assertNull($result->challengeToken);
    }
    public function testUnknownAndExistingUsersHaveIdenticalFailuresAndLockout(): void
    {
        $this->addUser();
        foreach (['alice', 'missing'] as $username) {
            for ($i = 0; $i < 3; $i++) {
                $r = $this->login->password($username, 'wrong', 'ip', 'browser');
                self::assertSame(Status::InvalidCredentials, $r->status);
                self::assertNull($r->userId);
            }
            $r = $this->login->password($username, 'wrong', 'ip', 'browser');
            self::assertSame(Status::Locked, $r->status);
            self::assertSame(60, $r->retryAfter);
            self::assertNull($r->userId);
        }
    }
    public function testIpAndUsernameIsolationAndCaseNormalization(): void
    {
        for ($i = 0; $i < 3; $i++) $this->login->password('missing', 'x', 'one', 'browser');
        self::assertSame(Status::Locked, $this->login->password(' MISSING ', 'x', 'one', 'browser')->status);
        self::assertSame(Status::InvalidCredentials, $this->login->password('missing', 'x', 'two', 'browser')->status);
        self::assertSame(Status::InvalidCredentials, $this->login->password('other', 'x', 'one', 'browser')->status);
    }
    public function testRollingWindowExpiresWithoutExtensionFromBlockedRequests(): void
    {
        for ($i = 0; $i < 3; $i++) $this->login->password('missing', 'x', 'ip', 'browser');
        $this->clock->timestamp += 59;
        self::assertSame(1, $this->login->password('missing', 'x', 'ip', 'browser')->retryAfter);
        $this->clock->timestamp++;
        self::assertSame(Status::InvalidCredentials, $this->login->password('missing', 'x', 'ip', 'browser')->status);
    }
    public function testSuccessClearsPriorFailures(): void
    {
        $this->addUser();
        $this->login->password('alice', 'wrong', 'ip', 'browser');
        $this->login->password('alice', 'wrong', 'ip', 'browser');
        self::assertSame(Status::Authenticated, $this->login->password('alice', 'correct', 'ip', 'browser')->status);
        self::assertSame(Status::InvalidCredentials, $this->login->password('alice', 'wrong', 'ip', 'browser')->status);
    }
    public function testDisabledAndPasswordlessUsersDoNotAuthenticate(): void
    {
        $this->addUser(disabled: true);
        self::assertSame(Status::InvalidCredentials, $this->login->password('alice', 'correct', 'ip', 'browser')->status);
        $this->users->items['42'] = new User('42', 'alice', null);
        self::assertSame(Status::InvalidCredentials, $this->login->password('alice', 'password', 'ip', 'browser')->status);
    }
    public function testPasswordExpiryIsOnlyRevealedAfterCorrectPassword(): void
    {
        $this->addUser(expires: $this->clock->timestamp);
        self::assertSame(Status::InvalidCredentials, $this->login->password('alice', 'wrong', 'ip', 'browser')->status);
        $r = $this->login->password('alice', 'correct', 'ip', 'browser');
        self::assertSame(Status::PasswordExpired, $r->status);
        self::assertNull($r->userId);
    }
    public function testTotpIsRequiredAndChallengeIsSingleUse(): void
    {
        $u = $this->addUser(mfa: true);
        $r = $this->login->password('alice', 'correct', 'ip', 'browser');
        self::assertSame(Status::SecondFactorRequired, $r->status);
        self::assertNull($r->userId);
        $code = TOTP::createFromSecret($u->totpSecret)->at($this->clock->timestamp);
        $done = $this->login->secondFactor($r->challengeToken, $code, 'ip', 'browser');
        self::assertSame(Status::Authenticated, $done->status);
        self::assertSame('42', $done->userId);
        self::assertSame(Status::InvalidCredentials, $this->login->secondFactor($r->challengeToken, $code, 'ip', 'browser')->status);
    }
    public function testTotpCannotBeReplayedAcrossChallengesOrIps(): void
    {
        $u = $this->addUser(mfa: true);
        $code = TOTP::createFromSecret($u->totpSecret)->at($this->clock->timestamp);
        foreach (['one', 'two'] as $i => $ip) {
            $r = $this->login->password('alice', 'correct', $ip, 'browser');
            self::assertSame($i === 0 ? Status::Authenticated : Status::InvalidCredentials, $this->login->secondFactor($r->challengeToken, $code, $ip, 'browser')->status);
        }
    }
    public function testChallengeBindingExpiryAndFailedCodeConsumption(): void
    {
        $this->addUser(mfa: true);
        $r = $this->login->password('alice', 'correct', 'ip', 'browser');
        self::assertSame(Status::InvalidCredentials, $this->login->secondFactor($r->challengeToken, 'bad', 'ip', 'attacker')->status);
        self::assertSame(Status::InvalidCredentials, $this->login->secondFactor($r->challengeToken, 'bad', 'other-ip', 'browser')->status);
        self::assertSame(Status::InvalidCredentials, $this->login->secondFactor($r->challengeToken, 'bad', 'ip', 'browser')->status);
        self::assertNull($this->challenges->consume($r->challengeToken, 'totp', 'browser'));
        $r = $this->login->password('alice', 'correct', 'ip', 'browser');
        $this->clock->timestamp += 30;
        self::assertSame(Status::InvalidCredentials, $this->login->secondFactor($r->challengeToken, '000000', 'ip', 'browser')->status);
    }
    public function testPendingLoginInvalidatedWhenPasswordChanges(): void
    {
        $u = $this->addUser(mfa: true);
        $r = $this->login->password('alice', 'correct', 'ip', 'browser');
        $this->users->items['42'] = new User('42', 'alice', password_hash('new', PASSWORD_BCRYPT), totpSecret: $u->totpSecret);
        $code = TOTP::createFromSecret($u->totpSecret)->at($this->clock->timestamp);
        self::assertSame(Status::InvalidCredentials, $this->login->secondFactor($r->challengeToken, $code, 'ip', 'browser')->status);
    }
}
