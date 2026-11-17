<?php
declare(strict_types=1);
namespace Light\Auth;
final readonly class Policy
{
    public function __construct(public int $maxAttempts = 5, public int $windowSeconds = 900, public int $challengeSeconds = 300)
    {
        if (min($maxAttempts, $windowSeconds, $challengeSeconds) < 1) {
            throw new \InvalidArgumentException('Authentication limits must be positive.');
        }
    }
}
