<?php
declare(strict_types=1);

namespace Light\Auth;

/** Validates a new password before it is stored. */
final readonly class PasswordPolicy
{
    public function __construct(
        public int $minLength = 0,
        public bool $requireUppercase = false,
        public bool $requireLowercase = false,
        public bool $requireNumeric = false,
        public bool $requireSymbol = false,
    ) {}

    /** @return list<string> Rules suitable for displaying the policy in an application. */
    public function rules(): array
    {
        $rules = ['required'];
        if ($this->requireUppercase) $rules[] = 'contains_uppercase';
        if ($this->requireLowercase) $rules[] = 'contains_lowercase';
        if ($this->requireNumeric) $rules[] = 'contains_numeric';
        if ($this->requireSymbol) $rules[] = 'contains_symbol';
        if ($this->minLength > 0) $rules[] = 'length:' . $this->minLength;
        return $rules;
    }

    /** @return list<string> The configured rules that the password fails. */
    public function violations(#[\SensitiveParameter] string $password): array
    {
        $failures = [];
        if ($password === '' || $password === '0') $failures[] = 'required';
        if ($this->requireUppercase && !preg_match('/[A-Z]/', $password)) $failures[] = 'contains_uppercase';
        if ($this->requireLowercase && !preg_match('/[a-z]/', $password)) $failures[] = 'contains_lowercase';
        if ($this->requireNumeric && !preg_match('/[0-9]/', $password)) $failures[] = 'contains_numeric';
        if ($this->requireSymbol && !preg_match('/[!@#$%^&*()\-_=+{};:,<.>]/', $password)) $failures[] = 'contains_symbol';
        if (strlen($password) < $this->minLength) $failures[] = 'length:' . $this->minLength;
        return $failures;
    }

    public function accepts(#[\SensitiveParameter] string $password): bool
    {
        return $this->violations($password) === [];
    }
}
