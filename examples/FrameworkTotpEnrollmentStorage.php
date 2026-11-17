<?php
declare(strict_types=1);

namespace Light\Auth\Example;

use Light\Auth\ConfirmedTotpEnrollment;
use Light\Db\Database;
use Light\Framework\Model\User;

/** Application-side example, not part of the library's runtime dependencies. */
final class FrameworkTotpEnrollmentStorage
{
    public function save(ConfirmedTotpEnrollment $confirmed): bool
    {
        $pdo = Database::getDefault()->connection();
        if ($pdo->inTransaction()) {
            throw new \LogicException('Call this example outside an existing transaction.');
        }

        $pdo->beginTransaction();
        try {
            // Serialize with other enrollment writes; never replace an already enabled secret.
            $query = $pdo->prepare('SELECT user_id, status, secret FROM `User` WHERE user_id = ? FOR UPDATE');
            $query->execute([$confirmed->userId]);
            $row = $query->fetch(\PDO::FETCH_ASSOC);
            if (!$row || $row['status'] != 0 || ($row['secret'] !== null && $row['secret'] !== '')) {
                $pdo->rollBack();
                return false;
            }

            $user = User::Get($confirmed->userId);
            if (!$user) {
                $pdo->rollBack();
                return false;
            }
            $user->secret = $confirmed->secret;
            $user->save(); // Preserve the application's model/audit behavior.
            $pdo->commit();
            return true;
        } catch (\Throwable $error) {
            if ($pdo->inTransaction()) $pdo->rollBack();
            throw $error;
        }
    }
}
