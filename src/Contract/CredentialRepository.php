<?php
declare(strict_types=1);
namespace Light\Auth\Contract;
use Light\Auth\WebAuthn\StoredCredential;
interface CredentialRepository
{
    // Credential IDs are binary, not base64 strings.
    public function find(string $credentialId): ?StoredCredential;
    // Atomically persist an updated credential only if its previous serialized record still matches.
    public function replace(StoredCredential $previous, string $updatedRecord): bool;
}
