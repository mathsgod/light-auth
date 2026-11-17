<?php
declare(strict_types=1);

namespace Light\Auth\Tests;

use Light\Auth\Contract\CredentialInventory;
use Light\Auth\WebAuthn\StoredCredential;

final class MemoryCredentials implements CredentialInventory
{
    /** @var array<string, StoredCredential> */
    public array $items = [];

    public function find(string $credentialId): ?StoredCredential { return $this->items[$credentialId] ?? null; }

    public function forUser(string $userId): array
    {
        return array_values(array_filter($this->items, static fn (StoredCredential $item): bool => $item->userId === $userId));
    }

    public function replace(StoredCredential $previous, string $updatedRecord): bool
    {
        if (($this->items[$previous->id] ?? null)?->record !== $previous->record) return false;
        $this->items[$previous->id] = new StoredCredential($previous->id, $previous->userId, $updatedRecord);
        return true;
    }
}
