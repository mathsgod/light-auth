<?php
declare(strict_types=1);

namespace Light\Auth\WebAuthn;

use Light\Auth\{AttemptLimiter, Challenges, User};
use Light\Auth\Contract\{CredentialInventory, UserRepository};
use Webauthn\{AuthenticatorAttestationResponse, AuthenticatorAttestationResponseValidator, AuthenticatorSelectionCriteria, CredentialRecord, PublicKeyCredential, PublicKeyCredentialCreationOptions, PublicKeyCredentialDescriptor, PublicKeyCredentialParameters, PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity};

/** Register passkeys for an authenticated, recently reverified application user. */
final class WebAuthnEnrollment
{
    private AuthenticatorAttestationResponseValidator $validator;

    /** @param list<string> $allowedOrigins */
    public function __construct(
        private UserRepository $users,
        private CredentialInventory $credentials,
        private Challenges $challenges,
        private AttemptLimiter $limiter,
        private string $rpId,
        private string $rpName,
        array $allowedOrigins,
    ) {
        if (trim($rpName) === '') throw new \InvalidArgumentException('RP name is required.');
        $factory = RelyingParty::factory($rpId, $allowedOrigins);
        $this->validator = AuthenticatorAttestationResponseValidator::create($factory->creationCeremony());
    }

    public function begin(string $userId, string $displayName, string $binding): RegistrationRequest
    {
        if ($userId === '' || trim($displayName) === '' || $binding === '') {
            throw new \InvalidArgumentException('User ID, display name and browser binding are required.');
        }
        $user = $this->users->findById($userId);
        if (!$user || $user->disabled) throw new \DomainException('User is not eligible for passkey enrollment.');

        $serializer = Serializer::create();
        $exclude = [];
        foreach ($this->credentials->forUser($userId) as $stored) {
            $record = $serializer->deserialize($stored->record, CredentialRecord::class, 'json');
            $exclude[] = PublicKeyCredentialDescriptor::create('public-key', $stored->id, $record->transports);
        }
        $options = PublicKeyCredentialCreationOptions::create(
            rp: PublicKeyCredentialRpEntity::create($this->rpName, $this->rpId),
            // Opaque, stable binary handle independent of username/email and DB identifier length.
            user: PublicKeyCredentialUserEntity::create($user->username, hash('sha256', $user->id, true), $displayName),
            challenge: random_bytes(32),
            pubKeyCredParams: [PublicKeyCredentialParameters::createPk(-7), PublicKeyCredentialParameters::createPk(-257)],
            authenticatorSelection: AuthenticatorSelectionCriteria::create(userVerification: 'required', residentKey: 'required'),
            attestation: 'none',
            excludeCredentials: $exclude,
            timeout: 60000,
        );
        $json = $serializer->serialize($options, 'json');
        $token = $this->challenges->issue('webauthn_registration', $this->binding($userId, $binding), [
            'options' => $json, 'version' => $this->version($user),
        ]);
        $publicKey = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
        // WebAuthn's browser dictionary must omit a null authenticatorAttachment.
        if (($publicKey['authenticatorSelection']['authenticatorAttachment'] ?? null) === null) {
            unset($publicKey['authenticatorSelection']['authenticatorAttachment']);
        }
        return new RegistrationRequest($token, $publicKey);
    }

    /** Returns a validated record for application-owned persistence, never a login session.
     * @param array<string, mixed> $attestation
     */
    public function confirm(string $userId, string $token, array $attestation, string $binding): ?StoredCredential
    {
        if ($userId === '' || $binding === '') return null;
        $data = $this->challenges->consume($token, 'webauthn_registration', $this->binding($userId, $binding));
        if (!$data) return null;
        $limitKey = 'webauthn_registration:' . $userId;
        if ($this->limiter->reserve($limitKey)) return null;
        $user = $this->users->findById($userId);
        if (!$user || $user->disabled || !hash_equals($data['version'], $this->version($user))) return null;

        $serializer = Serializer::create();
        try {
            $credential = $serializer->deserialize(json_encode($attestation, JSON_THROW_ON_ERROR), PublicKeyCredential::class, 'json');
        } catch (\Throwable) { return null; }
        if (!$credential->response instanceof AuthenticatorAttestationResponse) return null;
        if ($this->credentials->find($credential->rawId) !== null) return null;

        // Options come only from server-side challenge storage, never the browser.
        $options = $serializer->deserialize($data['options'], PublicKeyCredentialCreationOptions::class, 'json');
        try {
            $record = $this->validator->check($credential->response, $options, $this->rpId);
        } catch (\Throwable) { return null; }
        if (!hash_equals($record->publicKeyCredentialId, $credential->rawId)) return null;

        $result = new StoredCredential($record->publicKeyCredentialId, $userId, $serializer->serialize($record, 'json'));
        $this->limiter->clear($limitKey);
        return $result;
    }

    private function binding(string $userId, string $binding): string
    {
        return hash('sha256', json_encode([$userId, $binding], JSON_THROW_ON_ERROR));
    }

    private function version(User $user): string
    {
        return hash('sha256', json_encode([$user->passwordHash, $user->totpSecret, $user->passwordExpiresAt], JSON_THROW_ON_ERROR));
    }
}
