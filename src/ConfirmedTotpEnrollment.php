<?php
declare(strict_types=1);

namespace Light\Auth;

/** Server-side result for persistence; never return the confirmed secret to the browser. */
final readonly class ConfirmedTotpEnrollment
{
    public function __construct(
        public string $userId,
        #[\SensitiveParameter] public string $secret,
    ) {}

    /** @return array<string, string> */
    public function __debugInfo(): array
    {
        return ['userId' => $this->userId, 'secret' => '[redacted]'];
    }
}
