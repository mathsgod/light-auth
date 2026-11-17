<?php
declare(strict_types=1);
namespace Light\Auth\Contract;
use Light\Auth\User;
interface UserRepository
{
    // Both adapters and services use lowercase, trimmed usernames.
    public function findByUsername(string $username): ?User;
    public function findById(string $id): ?User;
}
