<?php
declare(strict_types=1);
namespace Light\Auth\Pdo;
use Light\Auth\Contract\UserRepository;
use Light\Auth\User;
/** Reads existing users; account provisioning and password updates stay with the application. */
final class PdoUserRepository implements UserRepository
{
    public function __construct(private \PDO $pdo, private UserMapping $mapping = new UserMapping())
    {
        $pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
    }
    public function findByUsername(string $username): ?User { return $this->find($this->mapping->username, strtolower(trim($username))); }
    public function findById(string $id): ?User { return $this->find($this->mapping->id, $id); }
    private function find(string $column, string $value): ?User
    {
        $fields = [];
        foreach (['id', 'username', 'passwordHash', 'disabled', 'passwordExpiresAt', 'totpSecret'] as $name) {
            $source = $this->mapping->$name;
            $fields[] = ($source === null ? 'NULL' : UserMapping::quote($source)) . ' AS ' . UserMapping::quote($name);
        }
        $query = $this->pdo->prepare('SELECT ' . implode(', ', $fields) . ' FROM ' . UserMapping::quote($this->mapping->table) . ' WHERE ' . UserMapping::quote($column) . ' = ?');
        $query->execute([$value]);
        $row = $query->fetch(\PDO::FETCH_ASSOC);
        if ($row === false) return null;
        $expires = $row['passwordExpiresAt'];
        if ($expires !== null && !is_numeric($expires)) throw new \UnexpectedValueException('passwordExpiresAt must map to a Unix timestamp; use a custom repository for datetime policies.');
        return new User((string) $row['id'], $row['username'], $row['passwordHash'], (bool) $row['disabled'], $expires === null ? null : (int) $expires, $row['totpSecret'] === '' ? null : $row['totpSecret']);
    }
}
