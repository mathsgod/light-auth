<?php
declare(strict_types=1);

namespace Light\Auth\Example;

use Light\Auth\Contract\{CredentialRepository, StateStore};
use Light\Auth\WebAuthn\StoredCredential;
use Light\Db\Database;
use Light\Framework\Model\User;
use Ramsey\Uuid\Uuid;

/** Application-side MySQL integration; use this same shared lock for every credential registration write. */
final class FrameworkWebAuthnEnrollmentStorage
{
    public function __construct(private StateStore $state, private CredentialRepository $credentials) {}

    /** Accept only the record returned by server-side WebAuthnEnrollment::confirm(). */
    public function save(StoredCredential $verified, string $name): bool
    {
        // Serializes duplicate checks across users because the existing JSON field has no unique index on credential IDs.
        return $this->state->update('webauthn_registration_storage', 60, function (array &$state) use ($verified, $name): bool {
            $pdo = Database::getDefault()->connection();
            if ($pdo->inTransaction()) throw new \LogicException('Call this example outside an existing transaction.');
            $pdo->beginTransaction();
            try {
                $query = $pdo->prepare('SELECT user_id, status FROM `User` WHERE user_id = ? FOR UPDATE');
                $query->execute([$verified->userId]);
                $row = $query->fetch(\PDO::FETCH_ASSOC);
                if (!$row || $row['status'] != 0 || $this->credentials->find($verified->id) !== null) {
                    $pdo->rollBack();
                    return false;
                }

                $user = User::Get($verified->userId);
                if (!$user) {
                    $pdo->rollBack();
                    return false;
                }
                $items = $user->credential ?? [];
                if (!is_array($items)) throw new \UnexpectedValueException('Expected the existing JSON credential array.');
                $items[] = [
                    'uuid' => Uuid::uuid4()->toString(),
                    'name' => $name,
                    'credential' => json_decode($verified->record, true, 512, JSON_THROW_ON_ERROR),
                ];
                $user->credential = $items;
                $user->save(); // Preserve model audit behavior and existing credential metadata.
                $pdo->commit();
                return true;
            } catch (\Throwable $error) {
                if ($pdo->inTransaction()) $pdo->rollBack();
                throw $error;
            }
        });
    }
}
