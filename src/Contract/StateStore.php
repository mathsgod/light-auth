<?php
declare(strict_types=1);
namespace Light\Auth\Contract;
interface StateStore
{
    /** Execute an atomic read/modify/write operation. Throw on storage or lock failure.
     * @template T
     * @param callable(array<string, mixed>&): T $operation
     * @return T
     */
    public function update(string $key, int $ttl, callable $operation): mixed;
}
