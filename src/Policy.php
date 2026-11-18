<?php
declare(strict_types=1);
namespace Light\Auth;
final readonly class Policy
{
    public function __construct(
        public int $maxAttempts = 5,
        public int $windowSeconds = 900,
        public int $challengeSeconds = 300,
        public RateLimitScope $scope = RateLimitScope::UsernameIp,
        public int $accountMaxAttempts = 20,
    )
    {
        if (min($maxAttempts, $windowSeconds, $challengeSeconds, $accountMaxAttempts) < 1) {
            throw new \InvalidArgumentException('Authentication limits must be positive.');
        }
    }
}
