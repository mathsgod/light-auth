<?php
declare(strict_types=1);
namespace Light\Auth\Tests;
use Light\Auth\{AttemptLimiter, Challenges, LoginService, Policy, TotpVerifier, User};
use Light\Auth\Cache\CacheStateStore;
use Light\Auth\Contract\UserRepository;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\Cache\Psr16Cache;
use Symfony\Component\Lock\{LockFactory, Store\FlockStore};
abstract class AuthTestCase extends TestCase
{
    protected FrozenClock $clock;
    protected CacheStateStore $state;
    protected AttemptLimiter $limiter;
    protected Challenges $challenges;
    protected TotpVerifier $totp;
    protected UserRepository $users;
    protected LoginService $login;
    protected function setUp(): void
    {
        $this->clock = new FrozenClock();
        $this->state = new CacheStateStore(new Psr16Cache(new ArrayAdapter()), new LockFactory(new FlockStore()));
        $policy = new Policy(3, 60, 30);
        $this->limiter = new AttemptLimiter($this->state, $policy, $this->clock);
        $this->challenges = new Challenges($this->state, $policy, $this->clock);
        $this->totp = new TotpVerifier($this->state, $this->clock);
        $this->users = new class implements UserRepository {
            /** @var array<string, User> */
            public array $items = [];
            public function findByUsername(string $username): ?User
            {
                foreach ($this->items as $item) if ($item->username === $username) return $item;
                return null;
            }
            public function findById(string $id): ?User { return $this->items[$id] ?? null; }
        };
        $this->login = new LoginService($this->users, $this->limiter, $this->challenges, $this->totp, $this->clock);
    }
    protected function addUser(bool $mfa = false, bool $disabled = false, ?int $expires = null): User
    {
        $user = new User('42', 'alice', password_hash('correct', PASSWORD_BCRYPT, ['cost' => 10]), $disabled, $expires, $mfa ? 'JBSWY3DPEHPK3PXP' : null);
        $this->users->items['42'] = $user;
        return $user;
    }
}
