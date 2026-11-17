<?php
declare(strict_types=1);

namespace Light\Auth\Tests;

use Light\Auth\{Policy, TotpEnrollment, TotpSetup, User};
use OTPHP\TOTP;

final class TotpEnrollmentTest extends AuthTestCase
{
    private TotpEnrollment $enrollment;

    protected function setUp(): void
    {
        parent::setUp();
        $this->enrollment = new TotpEnrollment($this->users, $this->state, new Policy(3, 60, 30), $this->totp, $this->clock);
    }

    private function begin(string $binding = 'browser'): TotpSetup
    {
        return $this->enrollment->begin('42', 'alice@example.test', 'My App', $binding);
    }

    private function secret(TotpSetup $setup): string
    {
        parse_str(parse_url($setup->provisioningUri, PHP_URL_QUERY), $parameters);
        return $parameters['secret'];
    }

    private function code(TotpSetup $setup): string
    {
        return TOTP::createFromSecret($this->secret($setup))->at($this->clock->timestamp);
    }

    public function testBeginReturnsProvisioningDataWithoutEnablingTotp(): void
    {
        $this->addUser();
        $setup = $this->begin();
        self::assertMatchesRegularExpression('/^[a-f0-9]{64}$/D', $setup->setupToken);
        self::assertSame($this->clock->timestamp + 30, $setup->expiresAt);
        self::assertStringStartsWith('otpauth://totp/', $setup->provisioningUri);
        parse_str(parse_url($setup->provisioningUri, PHP_URL_QUERY), $parameters);
        self::assertSame('My App', $parameters['issuer']);
        self::assertStringContainsString('alice%40example.test', $setup->provisioningUri);
        self::assertNull($this->users->findById('42')->totpSecret);
    }

    public function testConfirmationIsSingleUseAndApplicationOwnsPersistence(): void
    {
        $user = $this->addUser();
        $setup = $this->begin();
        $confirmed = $this->enrollment->confirm('42', $setup->setupToken, $this->code($setup), 'browser');
        self::assertNotNull($confirmed);
        self::assertSame('42', $confirmed->userId);
        self::assertSame($this->secret($setup), $confirmed->secret);
        self::assertNull($this->users->findById('42')->totpSecret);
        self::assertNull($this->enrollment->confirm('42', $setup->setupToken, $this->code($setup), 'browser'));

        // The application saves into its existing User store after confirmation.
        $enabled = new User($user->id, $user->username, $user->passwordHash, totpSecret: $confirmed->secret);
        $this->users->items['42'] = $enabled;
        self::assertFalse($this->totp->verify($enabled, $this->code($setup)), 'The enrollment code must not be reusable for login.');
        $this->clock->timestamp += 30;
        self::assertTrue($this->totp->verify($enabled, $this->code($setup)));
    }

    public function testWrongUserBrowserAndTokenCannotConfirmOrConsumeSetup(): void
    {
        $this->addUser();
        $this->users->items['99'] = new User('99', 'bob', null);
        $setup = $this->begin();
        $code = $this->code($setup);
        self::assertNull($this->enrollment->confirm('99', $setup->setupToken, $code, 'browser'));
        self::assertNull($this->enrollment->confirm('42', $setup->setupToken, $code, 'attacker-browser'));
        self::assertNull($this->enrollment->confirm('42', str_repeat('a', 64), $code, 'browser'));
        self::assertNull($this->enrollment->confirm('42', 'malformed', $code, 'browser'));
        self::assertNotNull($this->enrollment->confirm('42', $setup->setupToken, $code, 'browser'));
    }

    public function testWrongCodesCanBeRetriedUntilTheConfiguredLimit(): void
    {
        $this->addUser();
        $setup = $this->begin();
        self::assertNull($this->enrollment->confirm('42', $setup->setupToken, 'bad-code', 'browser'));
        self::assertNull($this->enrollment->confirm('42', $setup->setupToken, '', 'browser'));
        self::assertNotNull($this->enrollment->confirm('42', $setup->setupToken, $this->code($setup), 'browser'));
    }

    public function testAttemptLimitInvalidatesSetupEvenForSubsequentlyCorrectCode(): void
    {
        $this->addUser();
        $setup = $this->begin();
        for ($i = 0; $i < 3; $i++) {
            self::assertNull($this->enrollment->confirm('42', $setup->setupToken, 'bad-code', 'browser'));
        }
        self::assertNull($this->enrollment->confirm('42', $setup->setupToken, $this->code($setup), 'browser'));
        self::assertNull($this->users->findById('42')->totpSecret);
    }

    public function testExpiryIsNotExtendedByFailedConfirmation(): void
    {
        $this->addUser();
        $setup = $this->begin();
        $this->clock->timestamp += 29;
        self::assertNull($this->enrollment->confirm('42', $setup->setupToken, 'bad-code', 'browser'));
        $this->clock->timestamp++;
        self::assertNull($this->enrollment->confirm('42', $setup->setupToken, $this->code($setup), 'browser'));
    }

    public function testRestartInvalidatesEarlierSetupAndGeneratesANewSecret(): void
    {
        $this->addUser();
        $old = $this->begin();
        $new = $this->begin();
        self::assertNotSame($old->setupToken, $new->setupToken);
        self::assertNotSame($this->secret($old), $this->secret($new));
        self::assertNull($this->enrollment->confirm('42', $old->setupToken, $this->code($old), 'browser'));
        self::assertNotNull($this->enrollment->confirm('42', $new->setupToken, $this->code($new), 'browser'));
    }

    public function testExistingTotpCannotBeOverwritten(): void
    {
        $user = $this->addUser(mfa: true);
        $this->expectException(\DomainException::class);
        try {
            $this->begin();
        } finally {
            self::assertSame($user->totpSecret, $this->users->findById('42')->totpSecret);
        }
    }

    public function testUnknownAndDisabledUsersCannotBegin(): void
    {
        foreach ([null, new User('42', 'alice', null, disabled: true)] as $user) {
            $this->users->items = $user === null ? [] : ['42' => $user];
            try {
                $this->begin();
                self::fail('An ineligible user must not start enrollment.');
            } catch (\DomainException $e) {
                self::assertSame('User is not eligible for TOTP enrollment.', $e->getMessage());
            }
        }
    }

    public function testAccountChangesInvalidatePendingEnrollment(): void
    {
        foreach (['disabled', 'password', 'totp', 'deleted'] as $change) {
            $user = $this->addUser();
            $setup = $this->begin();
            if ($change === 'disabled') $this->users->items['42'] = new User('42', 'alice', $user->passwordHash, disabled: true);
            if ($change === 'password') $this->users->items['42'] = new User('42', 'alice', 'changed-hash');
            if ($change === 'totp') $this->users->items['42'] = new User('42', 'alice', $user->passwordHash, totpSecret: 'OTHERSECRET');
            if ($change === 'deleted') $this->users->items = [];
            self::assertNull($this->enrollment->confirm('42', $setup->setupToken, $this->code($setup), 'browser'));
            // Restoring the old account does not resurrect its invalidated setup.
            $this->users->items['42'] = $user;
            self::assertNull($this->enrollment->confirm('42', $setup->setupToken, $this->code($setup), 'browser'));
        }
    }

    public function testEmptyBrowserBindingIsRejected(): void
    {
        $this->addUser();
        $this->expectException(\InvalidArgumentException::class);
        $this->begin('');
    }
}
