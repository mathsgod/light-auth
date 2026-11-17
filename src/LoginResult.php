<?php
declare(strict_types=1);
namespace Light\Auth;
final readonly class LoginResult
{
    private function __construct(
        public Status $status,
        public ?string $userId = null,
        public ?string $challengeToken = null,
        public int $retryAfter = 0,
    ) {}
    public static function authenticated(string $userId): self { return new self(Status::Authenticated, $userId); }
    public static function invalid(): self { return new self(Status::InvalidCredentials); }
    public static function locked(int $seconds): self { return new self(Status::Locked, retryAfter: $seconds); }
    public static function expired(): self { return new self(Status::PasswordExpired); }
    public static function secondFactor(string $token): self { return new self(Status::SecondFactorRequired, challengeToken: $token); }
}
