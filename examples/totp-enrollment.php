<?php
declare(strict_types=1);

require dirname(__DIR__) . '/vendor/autoload.php';

use Light\Auth\{Policy, TotpEnrollment, TotpVerifier, User};
use Light\Auth\Cache\CacheStateStore;
use Light\Auth\Contract\UserRepository;
use OTPHP\TOTP;
use Symfony\Component\Cache\{Adapter\ArrayAdapter, Psr16Cache};
use Symfony\Component\Lock\{LockFactory, Store\FlockStore};

// CLI fixture only. HTTP applications supply a recently reverified session user.
$users = new class implements UserRepository {
    public User $user;
    public function __construct() { $this->user = new User('42', 'alice', null); }
    public function findByUsername(string $username): ?User { return $username === $this->user->username ? $this->user : null; }
    public function findById(string $id): ?User { return $id === $this->user->id ? $this->user : null; }
};
$state = new CacheStateStore(new Psr16Cache(new ArrayAdapter()), new LockFactory(new FlockStore()));
$enrollment = new TotpEnrollment($users, $state, new Policy(), new TotpVerifier($state));
$setup = $enrollment->begin('42', 'alice@example.test', 'My App', 'demo-browser-binding');
echo 'Before confirmation: ', $users->user->totpSecret === null ? 'disabled' : 'enabled', PHP_EOL;

// Simulate the Authenticator for this demo only. Real clients scan a QR code
// containing provisioningUri and submit their Authenticator's code.
parse_str(parse_url($setup->provisioningUri, PHP_URL_QUERY), $parameters);
$code = TOTP::createFromSecret($parameters['secret'])->now();
$confirmed = $enrollment->confirm('42', $setup->setupToken, $code, 'demo-browser-binding');
if ($confirmed === null) throw new \RuntimeException('Confirmation failed.');

// Application-owned persistence. A real repository writes to the existing User.
$users->user = new User('42', 'alice', null, totpSecret: $confirmed->secret);
echo 'After application saves: enabled', PHP_EOL;
echo 'Replayed confirmation: ', $enrollment->confirm('42', $setup->setupToken, $code, 'demo-browser-binding') === null ? 'rejected' : 'accepted', PHP_EOL;
