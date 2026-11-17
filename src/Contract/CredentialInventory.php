<?php
declare(strict_types=1);

namespace Light\Auth\Contract;

use Light\Auth\WebAuthn\StoredCredential;

/** Additional read capability for registration; existing assertion-only adapters stay compatible. */
interface CredentialInventory extends CredentialRepository
{
    /** @return list<StoredCredential> */
    public function forUser(string $userId): array;
}
