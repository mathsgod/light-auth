<?php
declare(strict_types=1);
namespace Light\Auth\Cache;
use Light\Auth\Contract\StateStore;
use Psr\SimpleCache\CacheInterface;
use Symfony\Component\Lock\LockFactory;
final class CacheStateStore implements StateStore
{
    public function __construct(private CacheInterface $cache, private LockFactory $locks, private string $namespace = 'light_auth') {}
    public function update(string $key, int $ttl, callable $operation): mixed
    {
        $key = $this->namespace . '_' . hash('sha256', $key);
        // An expiring distributed lock must be renewed by its store/caller if an operation can exceed its lease.
        $lock = $this->locks->createLock($key, 30.0);
        if (!$lock->acquire(true)) throw new \RuntimeException('Unable to acquire authentication state lock.');
        try {
            $state = $this->cache->get($key, []);
            if (!is_array($state)) throw new \RuntimeException('Invalid authentication state.');
            $result = $operation($state);
            if (!$this->cache->set($key, $state, $ttl)) throw new \RuntimeException('Unable to persist authentication state.');
            return $result;
        } finally {
            $lock->release();
        }
    }
}
