<?php
declare(strict_types=1);
namespace Light\Auth;
final readonly class User
{
    public function __construct(
        public string $id,
        public string $username,
        #[\SensitiveParameter] public ?string $passwordHash,
        public bool $disabled = false,
        public ?int $passwordExpiresAt = null,
        #[\SensitiveParameter] public ?string $totpSecret = null,
    ) {
        if ($id === '') throw new \InvalidArgumentException('User ID must not be empty.');
    }
}
