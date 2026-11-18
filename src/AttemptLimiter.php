<?php
declare(strict_types=1);
namespace Light\Auth;
use Light\Auth\Contract\StateStore;
use Psr\Clock\ClockInterface;
final class AttemptLimiter
{
    public function __construct(private StateStore $store, private Policy $policy, private ClockInterface $clock = new SystemClock()) {}
    public static function key(string $username, string $ip): string { return json_encode([strtolower(trim($username)), $ip], JSON_THROW_ON_ERROR); }

    public function loginKey(string $username, string $ip): string
    {
        return $this->policy->scope === RateLimitScope::Ip
            ? 'ip:' . json_encode($ip, JSON_THROW_ON_ERROR)
            : self::key($username, $ip);
    }

    public function loginSucceeded(string $key): void
    {
        // An IP quota must survive successful logins to prevent cross-account reset bypasses.
        if ($this->policy->scope === RateLimitScope::UsernameIp) $this->clear($key);
    }
    // Reserve before verification so concurrent requests also count toward the limit.
    public function reserve(string $key): int
    {
        $now = $this->clock->now()->getTimestamp();
        return $this->store->update('attempts:' . $key, $this->policy->windowSeconds, function (array &$state) use ($now): int {
            $times = array_values(array_filter($state['times'] ?? [], fn (int $time): bool => $time > $now - $this->policy->windowSeconds));
            $state['times'] = $times;
            if (count($times) >= $this->policy->maxAttempts) return max(1, $times[0] + $this->policy->windowSeconds - $now);
            $state['times'][] = $now;
            return 0;
        });
    }
    public function clear(string $key): void
    {
        $this->store->update('attempts:' . $key, $this->policy->windowSeconds, static function (array &$state): void { $state = []; });
    }
}
