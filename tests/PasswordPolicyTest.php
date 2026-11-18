<?php
declare(strict_types=1);

namespace Light\Auth\Tests;

use Light\Auth\PasswordPolicy;
use PHPUnit\Framework\TestCase;

final class PasswordPolicyTest extends TestCase
{
    public function testReportsConfiguredViolations(): void
    {
        $policy = new PasswordPolicy(8, true, true, true, true);

        self::assertSame(['contains_uppercase', 'contains_numeric', 'contains_symbol', 'length:8'], $policy->violations('abc?'));
        self::assertSame(['contains_lowercase'], $policy->violations('ABC1234!'));
        self::assertTrue($policy->accepts('Abc1234!'));
    }

    public function testPreservesFrameworkRequiredAndByteLengthSemantics(): void
    {
        self::assertFalse((new PasswordPolicy())->accepts(''));
        self::assertFalse((new PasswordPolicy())->accepts('0'));
        self::assertTrue((new PasswordPolicy(4))->accepts('密碼'));
    }
}
