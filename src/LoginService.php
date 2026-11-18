<?php
declare(strict_types=1);
namespace Light\Auth;
use Light\Auth\Contract\UserRepository;
use Psr\Clock\ClockInterface;
final class LoginService
{
    private static ?string $defaultDummyHash = null;
    private string $dummyPasswordHash;
    public function __construct(
        private UserRepository $users,
        private AttemptLimiter $limiter,
        private Challenges $challenges,
        private TotpVerifier $totp,
        private ClockInterface $clock = new SystemClock(),
        ?string $dummyPasswordHash = null,
    ) {
        $this->dummyPasswordHash = $dummyPasswordHash ?? (self::$defaultDummyHash ??= password_hash(bin2hex(random_bytes(32)), PASSWORD_DEFAULT));
        if ((password_get_info($this->dummyPasswordHash)['algo'] ?? null) === null) throw new \InvalidArgumentException('A valid dummy password hash is required.');
    }
    public function password(string $username, #[\SensitiveParameter] string $password, string $ip, string $binding): LoginResult
    {
        $username = strtolower(trim($username));
        $key = $this->limiter->loginKey($username, $ip);
        if ($retry = $this->limiter->reserve($key)) return LoginResult::locked($retry);
        $user = $this->users->findByUsername($username);
        $valid = password_verify($password, $user->passwordHash ?? $this->dummyPasswordHash);
        if (!$user || !$user->passwordHash || !$valid || $user->disabled) return LoginResult::invalid();
        if ($user->passwordExpiresAt !== null && $user->passwordExpiresAt <= $this->clock->now()->getTimestamp()) return LoginResult::expired();
        if ($user->totpSecret !== null) {
            $token = $this->challenges->issue('totp', self::binding($binding, $ip), [
                'userId' => $user->id, 'username' => $username, 'ip' => $ip,
                // Invalidate pending login if credentials or policy change before step two.
                'version' => self::version($user),
            ]);
            return LoginResult::secondFactor($token);
        }
        $this->limiter->loginSucceeded($key);
        return LoginResult::authenticated($user->id);
    }
    public function secondFactor(string $token, #[\SensitiveParameter] string $code, string $ip, string $binding): LoginResult
    {
        $data = $this->challenges->consume($token, 'totp', self::binding($binding, $ip));
        if (!$data || $data['ip'] !== $ip) return LoginResult::invalid();
        $user = $this->users->findById($data['userId']);
        if (!$user || $user->disabled || !hash_equals($data['version'], self::version($user))) return LoginResult::invalid();
        if ($user->passwordExpiresAt !== null && $user->passwordExpiresAt <= $this->clock->now()->getTimestamp()) return LoginResult::expired();
        if (!$this->totp->verify($user, $code)) return LoginResult::invalid();
        $this->limiter->loginSucceeded($this->limiter->loginKey($data['username'], $ip));
        return LoginResult::authenticated($user->id);
    }
    private static function binding(string $binding, string $ip): string
    {
        return hash('sha256', json_encode([$binding, $ip], JSON_THROW_ON_ERROR));
    }
    private static function version(User $user): string
    {
        return hash('sha256', json_encode([$user->passwordHash, $user->totpSecret, $user->passwordExpiresAt], JSON_THROW_ON_ERROR));
    }
}
