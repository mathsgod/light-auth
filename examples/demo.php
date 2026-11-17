<?php
declare(strict_types=1);
require dirname(__DIR__) . '/vendor/autoload.php';

use Light\Auth\{AttemptLimiter, Challenges, LoginService, Policy, TotpVerifier, User};
use Light\Auth\Cache\CacheStateStore;
use Light\Auth\Contract\UserRepository;
use Symfony\Component\Cache\{Adapter\ArrayAdapter, Psr16Cache};
use Symfony\Component\Lock\{LockFactory, Store\FlockStore};

// Demo fixture only. Replace this adapter with the existing application's repository.
$users = new class implements UserRepository {
    private User $user;
    public function __construct() { $this->user = new User('42', 'alice', password_hash('correct', PASSWORD_DEFAULT)); }
    public function findByUsername(string $username): ?User { return $username === 'alice' ? $this->user : null; }
    public function findById(string $id): ?User { return $id === '42' ? $this->user : null; }
};
$state = new CacheStateStore(new Psr16Cache(new ArrayAdapter()), new LockFactory(new FlockStore()));
$policy = new Policy(maxAttempts: 3);
$login = new LoginService($users, new AttemptLimiter($state, $policy), new Challenges($state, $policy), new TotpVerifier($state));
foreach (['alice', 'missing'] as $username) {
    for ($i = 1; $i <= 4; $i++) {
        $result = $login->password($username, 'wrong', '127.0.0.1', 'demo-browser-binding');
        echo $username, ' attempt ', $i, ': ', $result->status->value, PHP_EOL;
    }
}
$result = $login->password('alice', 'correct', '127.0.0.2', 'demo-browser-binding');
echo 'Correct password from another IP: ', $result->status->value, ' (user ', $result->userId, ')', PHP_EOL;
