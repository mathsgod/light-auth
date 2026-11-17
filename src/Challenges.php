<?php
declare(strict_types=1);
namespace Light\Auth;
use Light\Auth\Contract\StateStore;
use Psr\Clock\ClockInterface;
final class Challenges
{
    public function __construct(private StateStore $store, private Policy $policy, private ClockInterface $clock = new SystemClock()) {}
    /** @param array<string, mixed> $data */
    public function issue(string $purpose, string $binding, array $data): string
    {
        if ($binding === '') throw new \InvalidArgumentException('A browser/session binding is required.');
        $token = bin2hex(random_bytes(32));
        $expires = $this->clock->now()->getTimestamp() + $this->policy->challengeSeconds;
        $this->store->update('challenge:' . $token, $this->policy->challengeSeconds, static function (array &$state) use ($purpose, $binding, $data, $expires): void {
            $state = compact('purpose', 'binding', 'data', 'expires');
        });
        return $token;
    }
    /** A valid binding consumes the token even when subsequent verification fails.
     * @return array<string, mixed>|null
     */
    public function consume(string $token, string $purpose, string $binding): ?array
    {
        if (!preg_match('/^[a-f0-9]{64}$/D', $token)) return null;
        $now = $this->clock->now()->getTimestamp();
        return $this->store->update('challenge:' . $token, $this->policy->challengeSeconds, static function (array &$state) use ($purpose, $binding, $now): ?array {
            if (($state['purpose'] ?? null) !== $purpose || !hash_equals($state['binding'] ?? '', $binding)) return null;
            $data = ($state['expires'] ?? 0) > $now ? $state['data'] : null;
            $state = [];
            return $data;
        });
    }
}
