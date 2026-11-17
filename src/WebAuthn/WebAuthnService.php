<?php
declare(strict_types=1);
namespace Light\Auth\WebAuthn;
use Light\Auth\{AttemptLimiter, Challenges, LoginResult};
use Light\Auth\Contract\{UserRepository, CredentialRepository};
use Webauthn\{AuthenticatorAssertionResponse, AuthenticatorAssertionResponseValidator, CredentialRecord, PublicKeyCredential, PublicKeyCredentialRequestOptions};
final class WebAuthnService
{
    private AuthenticatorAssertionResponseValidator $validator;
    /** @param list<string> $allowedOrigins */
    public function __construct(
        private UserRepository $users,
        private CredentialRepository $credentials,
        private Challenges $challenges,
        private AttemptLimiter $limiter,
        private string $rpId,
        array $allowedOrigins,
    ) {
        $factory = RelyingParty::factory($rpId, $allowedOrigins);
        $this->validator = AuthenticatorAssertionResponseValidator::create($factory->requestCeremony());
    }
    // Discoverable credentials: no username lookup or account-dependent allowCredentials list.
    public function begin(string $binding): AssertionRequest
    {
        $serializer = Serializer::create();
        $options = PublicKeyCredentialRequestOptions::create(random_bytes(32), $this->rpId, [], 'required', 60000);
        $json = $serializer->serialize($options, 'json');
        $token = $this->challenges->issue('webauthn', $binding, ['options' => $json]);
        return new AssertionRequest($token, json_decode($json, true, 512, JSON_THROW_ON_ERROR));
    }
    /** @param array<string, mixed> $assertion */
    public function complete(string $token, array $assertion, string $ip, string $binding): LoginResult
    {
        $key = AttemptLimiter::key('webauthn', $ip);
        if ($retry = $this->limiter->reserve($key)) return LoginResult::locked($retry);
        $data = $this->challenges->consume($token, 'webauthn', $binding);
        if (!$data) return LoginResult::invalid();
        $serializer = Serializer::create();
        // Repository/cache errors deliberately propagate; only invalid protocol input is mapped to failure.
        try {
            $credential = $serializer->deserialize(json_encode($assertion, JSON_THROW_ON_ERROR), PublicKeyCredential::class, 'json');
        } catch (\Throwable) { return LoginResult::invalid(); }
        if (!$credential->response instanceof AuthenticatorAssertionResponse) return LoginResult::invalid();
        $stored = $this->credentials->find($credential->rawId);
        if (!$stored) return LoginResult::invalid();
        $user = $this->users->findById($stored->userId);
        if (!$user || $user->disabled) return LoginResult::invalid();
        $record = $serializer->deserialize($stored->record, CredentialRecord::class, 'json');
        $options = $serializer->deserialize($data['options'], PublicKeyCredentialRequestOptions::class, 'json');
        if (!hash_equals($record->publicKeyCredentialId, $credential->rawId)) return LoginResult::invalid();
        try {
            $updated = $this->validator->check($record, $credential->response, $options, $this->rpId, null);
        } catch (\Throwable) { return LoginResult::invalid(); }
        if (!$this->credentials->replace($stored, $serializer->serialize($updated, 'json'))) return LoginResult::invalid();
        $this->limiter->clear($key);
        return LoginResult::authenticated($user->id);
    }
}
