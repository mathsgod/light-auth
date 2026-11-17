<?php
declare(strict_types=1);
namespace Light\Auth\Pdo;
use Light\Auth\Contract\CredentialInventory;
use Light\Auth\WebAuthn\StoredCredential;
use ParagonIE\ConstantTime\Base64UrlSafe;
/** Reuses a JSON credential array on the existing user table; creates no tables. */
final class PdoCredentialRepository implements CredentialInventory
{
    public function __construct(
        private \PDO $pdo,
        private string $table = 'User',
        private string $idColumn = 'user_id',
        private string $credentialColumn = 'credential',
        private ?string $wrapperKey = 'credential',
    ) {
        UserMapping::quote($table);
        UserMapping::quote($idColumn);
        UserMapping::quote($credentialColumn);
        $pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
    }
    public function find(string $credentialId): ?StoredCredential
    {
        $q = $this->pdo->query('SELECT ' . UserMapping::quote($this->idColumn) . ' AS owner, ' . UserMapping::quote($this->credentialColumn) . ' AS payload FROM ' . UserMapping::quote($this->table) . ' WHERE ' . UserMapping::quote($this->credentialColumn) . ' IS NOT NULL');
        foreach ($q as $row) {
            foreach ($this->decode($row['payload']) as $item) {
                $record = $this->wrapperKey === null ? $item : $item[$this->wrapperKey];
                if (($record['publicKeyCredentialId'] ?? null) === Base64UrlSafe::encodeUnpadded($credentialId)) {
                    return new StoredCredential($credentialId, (string) $row['owner'], json_encode($record, JSON_THROW_ON_ERROR));
                }
            }
        }
        return null;
    }
    /** @return list<StoredCredential> */
    public function forUser(string $userId): array
    {
        $q = $this->pdo->prepare('SELECT ' . UserMapping::quote($this->credentialColumn) . ' FROM ' . UserMapping::quote($this->table) . ' WHERE ' . UserMapping::quote($this->idColumn) . ' = ?');
        $q->execute([$userId]);
        $payload = $q->fetchColumn();
        if (!is_string($payload)) return [];
        $credentials = [];
        foreach ($this->decode($payload) as $item) {
            $record = $this->wrapperKey === null ? $item : $item[$this->wrapperKey];
            $credentials[] = new StoredCredential(Base64UrlSafe::decodeNoPadding($record['publicKeyCredentialId']), $userId, json_encode($record, JSON_THROW_ON_ERROR));
        }
        return $credentials;
    }
    public function replace(StoredCredential $previous, string $updatedRecord): bool
    {
        $table = UserMapping::quote($this->table);
        $id = UserMapping::quote($this->idColumn);
        $column = UserMapping::quote($this->credentialColumn);
        $q = $this->pdo->prepare("SELECT $column FROM $table WHERE $id = ?");
        $q->execute([$previous->userId]);
        $original = $q->fetchColumn();
        if (!is_string($original)) return false;
        $items = $this->decode($original);
        $found = false;
        foreach ($items as &$item) {
            $record = $this->wrapperKey === null ? $item : $item[$this->wrapperKey];
            if (($record['publicKeyCredentialId'] ?? null) !== Base64UrlSafe::encodeUnpadded($previous->id)) continue;
            if (json_encode($record, JSON_THROW_ON_ERROR) !== $previous->record) return false;
            $updated = json_decode($updatedRecord, true, 512, JSON_THROW_ON_ERROR);
            if ($this->wrapperKey === null) $item = $updated;
            else $item[$this->wrapperKey] = $updated;
            $found = true;
            break;
        }
        unset($item);
        if (!$found) return false;
        $payload = json_encode($items, JSON_THROW_ON_ERROR);
        // MySQL JSON formatting/collations differ from SQLite text. Compare the bytes read, not a user-supplied version.
        $mysql = $this->pdo->getAttribute(\PDO::ATTR_DRIVER_NAME) === 'mysql';
        $predicate = $mysql ? "BINARY CAST($column AS CHAR) = BINARY ?" : "$column = ? COLLATE BINARY";
        $q = $this->pdo->prepare("UPDATE $table SET $column = ? WHERE $id = ? AND $predicate");
        $q->execute([$payload, $previous->userId, $original]);
        // A counter-less authenticator may produce an unchanged record. The compare-and-swap still matched.
        if ($q->rowCount() === 1) return true;
        return $payload === $original && $this->find($previous->id)?->record === $previous->record;
    }
    /** @return list<array<string, mixed>> */
    private function decode(string $payload): array
    {
        if ($payload === '') return [];
        $value = json_decode($payload, true, 512, JSON_THROW_ON_ERROR);
        if (!is_array($value) || !array_is_list($value)) throw new \UnexpectedValueException('Credentials must be a JSON array.');
        return $value;
    }
}
