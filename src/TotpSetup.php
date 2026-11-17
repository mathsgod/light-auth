<?php
declare(strict_types=1);

namespace Light\Auth;

final readonly class TotpSetup
{
    public function __construct(
        public string $setupToken,
        public string $provisioningUri,
        public int $expiresAt,
    ) {}
}
