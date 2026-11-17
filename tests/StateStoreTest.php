<?php
declare(strict_types=1);
namespace Light\Auth\Tests;
use Light\Auth\{AttemptLimiter, Challenges, Policy};
use Light\Auth\Cache\CacheStateStore;
use PHPUnit\Framework\TestCase;
use Psr\SimpleCache\CacheInterface;
use Symfony\Component\Cache\{Adapter\FilesystemAdapter, Psr16Cache};
use Symfony\Component\Lock\{LockFactory, Store\FlockStore};
final class StateStoreTest extends TestCase
{
    public function testCacheWriteFailureDoesNotReturnAuthenticationState(): void
    {
        $cache = $this->createStub(CacheInterface::class);
        $cache->method('get')->willReturn([]);
        $cache->method('set')->willReturn(false);
        $store = new CacheStateStore($cache, new LockFactory(new FlockStore()));
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Unable to persist');
        (new Challenges($store, new Policy()))->issue('totp', 'browser', ['userId' => '1']);
    }
    public function testConcurrentAttemptsAndChallengeConsumptionAreAtomic(): void
    {
        if (!function_exists('pcntl_fork')) self::markTestSkipped('pcntl required.');
        $dir = sys_get_temp_dir() . '/light-auth-test-' . bin2hex(random_bytes(8));
        mkdir($dir, 0700);
        $cache = new Psr16Cache(new FilesystemAdapter('auth', 0, $dir));
        $state = new CacheStateStore($cache, new LockFactory(new FlockStore($dir)));
        $policy = new Policy(3, 60, 30);
        $challenges = new Challenges($state, $policy);
        $token = $challenges->issue('test', 'browser', ['userId' => '42']);
        $children = [];
        try {
            for ($i = 0; $i < 8; $i++) {
                $pid = pcntl_fork();
                if ($pid === -1) throw new \RuntimeException('fork failed');
                if ($pid === 0) {
                    // Workers own adapters; do not inherit a filesystem adapter's temporary-file state.
                    $state = new CacheStateStore(new Psr16Cache(new FilesystemAdapter('auth', 0, $dir)), new LockFactory(new FlockStore($dir)));
                    $challenges = new Challenges($state, $policy);
                    $limiter = new AttemptLimiter($state, $policy);
                    $reserved = $limiter->reserve('same-user-and-ip') === 0;
                    $consumed = $challenges->consume($token, 'test', 'browser') !== null;
                    file_put_contents($dir . '/result-' . $i, json_encode([$reserved, $consumed]));
                    exit(0);
                }
                $children[] = $pid;
            }
            foreach ($children as $pid) {
                pcntl_waitpid($pid, $status);
                self::assertSame(0, pcntl_wexitstatus($status));
            }
            $reserved = $consumed = 0;
            for ($i = 0; $i < 8; $i++) {
                [$r, $c] = json_decode(file_get_contents($dir . '/result-' . $i), true);
                $reserved += (int) $r;
                $consumed += (int) $c;
            }
            self::assertSame(3, $reserved);
            self::assertSame(1, $consumed);
        } finally {
            $cache->clear();
            $entries = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS), \RecursiveIteratorIterator::CHILD_FIRST);
            foreach ($entries as $entry) $entry->isDir() ? rmdir($entry->getPathname()) : unlink($entry->getPathname());
            rmdir($dir);
        }
    }
}
