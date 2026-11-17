<?php
declare(strict_types=1);
namespace Light\Auth;
use Light\Auth\Contract\StateStore;
use OTPHP\TOTP;
use Psr\Clock\ClockInterface;
final class TotpVerifier
{
    public function __construct(private StateStore $store, private ClockInterface $clock = new SystemClock()) {}
    public function verify(User $user, #[\SensitiveParameter] string $code): bool
    {
        if (!$user->totpSecret || !preg_match('/^[0-9]{6}$/D', $code)) return false;
        $now = $this->clock->now()->getTimestamp();
        $otp = TOTP::createFromSecret($user->totpSecret);
        $step = intdiv($now, 30);
        // Accept current step only. A consumed step is shared across IPs and challenges.
        if (!$otp->verify($code, $now, 0)) return false;
        return $this->store->update('totp:' . $user->id, 90, static function (array &$state) use ($step): bool {
            if (($state['step'] ?? -1) >= $step) return false;
            $state['step'] = $step;
            return true;
        });
    }
}
