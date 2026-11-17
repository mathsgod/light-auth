<?php
declare(strict_types=1);

namespace Light\Auth\Example;

use Light\Auth\Contract\UserRepository;
use Light\Auth\User as AuthUser;
use Light\Framework\Model\User;

/** Example integration adapter, deliberately outside the library's src/autoload namespace. */
final class FrameworkUserRepository implements UserRepository
{
    // Read Config in the composition root and pass the policy explicitly.
    public function __construct(private ?int $passwordLifetimeDays = null) {}

    public function findByUsername(string $username): ?AuthUser
    {
        return $this->map(User::Get(['username' => $username]));
    }

    public function findById(string $id): ?AuthUser
    {
        return $this->map(User::Get($id));
    }

    private function map(?User $user): ?AuthUser
    {
        if ($user === null) return null;
        $expires = null;
        if ($this->passwordLifetimeDays !== null && $user->password_dt) {
            $expires = (new \DateTimeImmutable($user->password_dt))
                ->modify('+' . $this->passwordLifetimeDays . ' days')->getTimestamp();
        }
        return new AuthUser(
            id: (string) $user->user_id,
            username: $user->username,
            passwordHash: $user->password ?: null,
            disabled: $user->status != 0,
            passwordExpiresAt: $expires,
            totpSecret: $user->secret ?: null,
        );
    }
}
