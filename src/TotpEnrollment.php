<?php
declare(strict_types=1);

namespace Light\Auth;

use Light\Auth\Contract\StateStore;
use Light\Auth\Contract\UserRepository;
use OTPHP\TOTP;
use Psr\Clock\ClockInterface;

/** Call only after the application has authenticated and recently reverified the user. */
final class TotpEnrollment
{
    public function __construct(
        private UserRepository $users,
        private StateStore $store,
        private Policy $policy,
        private TotpVerifier $totp,
        private ClockInterface $clock = new SystemClock(),
    ) {}

    public function begin(string $userId, string $label, string $issuer, string $binding): TotpSetup
    {
        if ($binding === '' || trim($label) === '' || trim($issuer) === '') {
            throw new \InvalidArgumentException('Browser binding, label and issuer are required.');
        }

        $otp = TOTP::generate()->withLabel($label)->withIssuer($issuer);
        $token = bin2hex(random_bytes(32));
        $expires = $this->clock->now()->getTimestamp() + $this->policy->challengeSeconds;

        $this->store->update($this->key($userId), $this->policy->challengeSeconds, function (array &$state) use ($userId, $binding, $otp, $token, $expires): void {
            $user = $this->users->findById($userId);
            if (!$user || $user->disabled || $user->totpSecret !== null) {
                throw new \DomainException('User is not eligible for TOTP enrollment.');
            }

            // One pending enrollment per user. Restarting invalidates every earlier setup token.
            $state = [
                'tokenHash' => hash('sha256', $token),
                'bindingHash' => hash('sha256', $binding),
                'secret' => $otp->getSecret(),
                'expires' => $expires,
                'attempts' => 0,
                'version' => $this->version($user),
            ];
        });

        return new TotpSetup($token, $otp->getProvisioningUri(), $expires);
    }

    /** Returns null on rejection. Only a successful, single-use confirmation exposes a secret for storage. */
    public function confirm(
        string $userId,
        string $setupToken,
        #[\SensitiveParameter] string $code,
        string $binding,
    ): ?ConfirmedTotpEnrollment {
        if ($userId === '' || $binding === '' || !preg_match('/^[a-f0-9]{64}$/D', $setupToken)) {
            return null;
        }

        return $this->store->update($this->key($userId), $this->policy->challengeSeconds, function (array &$state) use ($userId, $setupToken, $code, $binding): ?ConfirmedTotpEnrollment {
            if ($state === []) return null;
            if ($state['expires'] <= $this->clock->now()->getTimestamp()) {
                $state = [];
                return null;
            }
            if (!hash_equals($state['tokenHash'], hash('sha256', $setupToken)) ||
                !hash_equals($state['bindingHash'], hash('sha256', $binding))) {
                return null;
            }

            $user = $this->users->findById($userId);
            if (!$user || $user->disabled || $user->totpSecret !== null ||
                !hash_equals($state['version'], $this->version($user))) {
                $state = [];
                return null;
            }

            $pendingUser = new User($user->id, $user->username, $user->passwordHash, totpSecret: $state['secret']);
            if (!$this->totp->verify($pendingUser, $code)) {
                if (++$state['attempts'] >= $this->policy->maxAttempts) $state = [];
                return null;
            }

            $confirmed = new ConfirmedTotpEnrollment($userId, $state['secret']);
            $state = [];
            return $confirmed;
        });
    }

    private function key(string $userId): string
    {
        if ($userId === '') throw new \InvalidArgumentException('User ID is required.');
        return 'totp_enrollment:' . $userId;
    }

    private function version(User $user): string
    {
        return hash('sha256', json_encode([$user->passwordHash, $user->passwordExpiresAt], JSON_THROW_ON_ERROR));
    }
}
