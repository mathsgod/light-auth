<?php
declare(strict_types=1);
namespace Light\Auth\Pdo;
/** Maps an application's existing user table. Null fields are not selected. */
final readonly class UserMapping
{
    public function __construct(
        public string $table = 'User',
        public string $id = 'user_id',
        public string $username = 'username',
        public string $passwordHash = 'password',
        public ?string $disabled = 'status',
        public ?string $passwordExpiresAt = null,
        public ?string $totpSecret = 'secret',
    ) {
        foreach (get_object_vars($this) as $value) {
            if ($value !== null) self::quote($value);
        }
    }
    public static function quote(string $identifier): string
    {
        if (!preg_match('/^[a-zA-Z_][a-zA-Z0-9_]*$/D', $identifier)) throw new \InvalidArgumentException('Invalid database identifier.');
        return '`' . $identifier . '`';
    }
}
