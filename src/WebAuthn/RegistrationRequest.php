<?php
declare(strict_types=1);

namespace Light\Auth\WebAuthn;

final readonly class RegistrationRequest
{
    /** @param array<string, mixed> $publicKey */
    public function __construct(public string $token, public array $publicKey) {}
}
