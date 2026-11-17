<?php
declare(strict_types=1);
namespace Light\Auth\WebAuthn;
final readonly class StoredCredential
{
    public function __construct(public string $id, public string $userId, public string $record) {}
}
