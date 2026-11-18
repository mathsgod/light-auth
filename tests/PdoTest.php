<?php
declare(strict_types=1);
namespace Light\Auth\Tests;
use Light\Auth\Pdo\{PdoUserRepository, PdoCredentialRepository, UserMapping};
use PHPUnit\Framework\TestCase;
final class PdoTest extends TestCase
{
    private \PDO $pdo;
    protected function setUp(): void
    {
        if (!in_array('sqlite', \PDO::getAvailableDrivers(), true)) self::markTestSkipped('pdo_sqlite required.');
        $this->pdo = new \PDO('sqlite::memory:');
        // Application-owned schema: no auth_* tables or package migrations.
        $this->pdo->exec('CREATE TABLE User (user_id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, status INTEGER, secret TEXT, credential TEXT)');
        $this->pdo->prepare('INSERT INTO User VALUES (?,?,?,?,?,?)')->execute([42, 'alice', password_hash('correct', PASSWORD_BCRYPT), 0, '', '[]']);
    }
    public function testReadsExistingUserTableWithoutCreatingTables(): void
    {
        $repo = new PdoUserRepository($this->pdo);
        self::assertSame('42', $repo->findByUsername('alice')->id);
        self::assertNull($repo->findById('42')->totpSecret);
        self::assertNull($repo->findByUsername('missing'));
        self::assertSame(['User'], $this->pdo->query("SELECT name FROM sqlite_master WHERE type='table'")->fetchAll(\PDO::FETCH_COLUMN));
    }
    public function testStarterSchemaWorksWithBothPdoRepositories(): void
    {
        $pdo = new \PDO('sqlite::memory:', options: [\PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION]);
        $pdo->exec(file_get_contents(dirname(__DIR__) . '/migrations/sqlite.sql'));
        $pdo->exec("INSERT INTO `User` (username, password_expires_at) VALUES ('alice', 1700000000)");

        $users = new PdoUserRepository($pdo, new UserMapping(passwordExpiresAt: 'password_expires_at'));
        $user = $users->findByUsername(' Alice ');
        self::assertNotNull($user);
        self::assertFalse($user->disabled);
        self::assertSame(1700000000, $user->passwordExpiresAt);
        self::assertSame([], (new PdoCredentialRepository($pdo, 'User', 'user_id', 'credential'))->forUser($user->id));
    }

    public function testCustomColumnMapping(): void
    {
        $this->pdo->exec('CREATE TABLE members (uuid TEXT, login TEXT, hash TEXT)');
        $this->pdo->prepare('INSERT INTO members VALUES (?,?,?)')->execute(['u1', 'bob', 'hash']);
        $repo = new PdoUserRepository($this->pdo, new UserMapping('members', 'uuid', 'login', 'hash', null, null, null));
        self::assertSame('u1', $repo->findByUsername('bob')->id);
        self::assertFalse($repo->findById('u1')->disabled);
    }

    public function testCredentialInventoryReadsOnlyTheRequestedUsersExistingJson(): void
    {
        $payload = [['uuid' => 'keep', 'credential' => ['publicKeyCredentialId' => 'aWQ', 'counter' => 1]]];
        $this->pdo->prepare('UPDATE User SET credential=? WHERE user_id=42')->execute([json_encode($payload)]);
        $repo = new PdoCredentialRepository($this->pdo, 'User', 'user_id', 'credential', wrapperKey: 'credential');
        $items = $repo->forUser('42');
        self::assertCount(1, $items);
        self::assertSame('id', $items[0]->id);
        self::assertSame('42', $items[0]->userId);
        self::assertSame($payload[0]['credential'], json_decode($items[0]->record, true));
        self::assertSame([], $repo->forUser('missing'));
    }

    public function testCredentialInventorySupportsUnwrappedJsonAndCustomColumns(): void
    {
        $this->pdo->exec('CREATE TABLE members (uuid TEXT, keys TEXT)');
        $this->pdo->prepare('INSERT INTO members VALUES (?,?)')->execute(['u1', json_encode([['publicKeyCredentialId' => 'aWQ', 'counter' => 1]])]);
        $repo = new PdoCredentialRepository($this->pdo, 'members', 'uuid', 'keys');
        self::assertSame('id', $repo->forUser('u1')[0]->id);
        self::assertSame('u1', $repo->forUser('u1')[0]->userId);
    }
    public function testRejectsSqlIdentifiers(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new UserMapping(table: 'User; DROP TABLE User');
    }
    public function testCredentialsReuseUserJsonPreserveMetadataAndRejectStaleUpdate(): void
    {
        $payload = [['uuid' => 'keep-me', 'name' => 'My passkey', 'credential' => ['publicKeyCredentialId' => 'aWQ', 'counter' => 1]], ['uuid' => 'other', 'credential' => ['publicKeyCredentialId' => 'b3RoZXI', 'counter' => 9]]];
        $this->pdo->prepare('UPDATE User SET credential=?')->execute([json_encode($payload)]);
        $repo = new PdoCredentialRepository($this->pdo, 'User', 'user_id', 'credential', wrapperKey: 'credential');
        $before = $repo->find('id');
        self::assertSame('42', $before->userId);
        self::assertNull($repo->find('missing'));
        self::assertTrue($repo->replace($before, json_encode(['publicKeyCredentialId' => 'aWQ', 'counter' => 2])));
        self::assertFalse($repo->replace($before, json_encode(['publicKeyCredentialId' => 'aWQ', 'counter' => 3])));
        $after = json_decode($this->pdo->query('SELECT credential FROM User')->fetchColumn(), true);
        self::assertSame('keep-me', $after[0]['uuid']);
        self::assertSame('My passkey', $after[0]['name']);
        self::assertSame($payload[1], $after[1]);
        self::assertSame(2, $after[0]['credential']['counter']);
    }
}
