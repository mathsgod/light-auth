<?php
declare(strict_types=1);

namespace Light\Auth\Tests;

use Light\Auth\{Status, User};
use Light\Auth\WebAuthn\{RegistrationRequest, Serializer, StoredCredential, WebAuthnEnrollment, WebAuthnService};
use ParagonIE\ConstantTime\Base64UrlSafe as B64;
use PHPUnit\Framework\Attributes\DataProvider;
use Webauthn\CredentialRecord;

final class WebAuthnEnrollmentTest extends AuthTestCase
{
    private MemoryCredentials $credentials;
    private WebAuthnEnrollment $enrollment;
    private PasskeyAuthenticator $authenticator;

    protected function setUp(): void
    {
        parent::setUp();
        $this->addUser();
        $this->credentials = new MemoryCredentials();
        $this->authenticator = new PasskeyAuthenticator();
        $this->enrollment = new WebAuthnEnrollment($this->users, $this->credentials, $this->challenges, $this->limiter, 'example.test', 'My App', ['https://example.test']);
    }

    private function begin(): RegistrationRequest { return $this->enrollment->begin('42', 'Alice', 'browser'); }

    public function testCreationRequiresDiscoverableCredentialAndUserVerificationWithoutSaving(): void
    {
        $request = $this->begin();
        self::assertSame('example.test', $request->publicKey['rp']['id']);
        self::assertSame('My App', $request->publicKey['rp']['name']);
        self::assertSame('Alice', $request->publicKey['user']['displayName']);
        self::assertSame(hash('sha256', '42', true), B64::decodeNoPadding($request->publicKey['user']['id']));
        self::assertSame('required', $request->publicKey['authenticatorSelection']['residentKey']);
        self::assertSame('required', $request->publicKey['authenticatorSelection']['userVerification']);
        self::assertArrayNotHasKey('authenticatorAttachment', $request->publicKey['authenticatorSelection']);
        self::assertSame('none', $request->publicKey['attestation']);
        self::assertSame([], $this->credentials->items);
    }

    public function testRegistrationThenApplicationPersistenceThenSignedAssertion(): void
    {
        $request = $this->begin();
        $attestation = $this->authenticator->attestation($request);
        $verified = $this->enrollment->confirm('42', $request->token, $attestation, 'browser');
        self::assertNotNull($verified);
        self::assertSame('42', $verified->userId);
        self::assertSame($this->authenticator->id, $verified->id);
        self::assertSame([], $this->credentials->items, 'Verification must not persist a credential.');
        self::assertNull($this->enrollment->confirm('42', $request->token, $attestation, 'browser'));

        // The application persists only the server-verified record.
        $this->credentials->items[$verified->id] = $verified;
        $source = Serializer::create()->deserialize($verified->record, CredentialRecord::class, 'json');
        $login = new WebAuthnService($this->users, $this->credentials, $this->challenges, $this->limiter, 'example.test', ['https://example.test']);
        $challenge = $login->begin('browser');
        $result = $login->complete($challenge->token, $this->authenticator->assertion($challenge, $source->userHandle), 'ip', 'browser');
        self::assertSame(Status::Authenticated, $result->status);
        self::assertSame('42', $result->userId);
    }

    public static function invalidAttestations(): iterable
    {
        foreach (['challenge', 'origin', 'rp', 'uv', 'up', 'rawId', 'type', 'algorithm'] as $value) yield $value => [$value];
    }

    #[DataProvider('invalidAttestations')]
    public function testInvalidAttestationIsRejectedAndConsumesItsChallenge(string $mutation): void
    {
        $request = $this->begin();
        self::assertNull($this->enrollment->confirm('42', $request->token, $this->authenticator->attestation($request, $mutation), 'browser'));
        self::assertNull($this->enrollment->confirm('42', $request->token, $this->authenticator->attestation($request), 'browser'));
        self::assertSame([], $this->credentials->items);
    }

    public function testTokenIsBoundToUserBrowserAndPurpose(): void
    {
        $this->users->items['99'] = new User('99', 'bob', null);
        $request = $this->begin();
        $attestation = $this->authenticator->attestation($request);
        self::assertNull($this->enrollment->confirm('99', $request->token, $attestation, 'browser'));
        self::assertNull($this->enrollment->confirm('42', $request->token, $attestation, 'other-browser'));
        $loginToken = $this->challenges->issue('webauthn', 'browser', []);
        self::assertNull($this->enrollment->confirm('42', $loginToken, $attestation, 'browser'));
        self::assertNotNull($this->enrollment->confirm('42', $request->token, $attestation, 'browser'));
    }

    public function testExpiredChallengeCannotRegister(): void
    {
        $request = $this->begin();
        $this->clock->timestamp += 30;
        self::assertNull($this->enrollment->confirm('42', $request->token, $this->authenticator->attestation($request), 'browser'));
    }

    public function testMalformedAndAssertionResponsesCannotRegister(): void
    {
        $request = $this->begin();
        self::assertNull($this->enrollment->confirm('42', $request->token, [], 'browser'));
        self::assertNull($this->enrollment->confirm('42', $request->token, $this->authenticator->attestation($request), 'browser'));

        $request = $this->begin();
        $login = new WebAuthnService($this->users, $this->credentials, $this->challenges, $this->limiter, 'example.test', ['https://example.test']);
        $assertion = $this->authenticator->assertion($login->begin('browser'), hash('sha256', '42', true));
        self::assertNull($this->enrollment->confirm('42', $request->token, $assertion, 'browser'));
    }

    public function testEmptyBrowserBindingIsRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->enrollment->begin('42', 'Alice', '');
    }

    public function testExistingCredentialIsExcludedAndCannotBeReassigned(): void
    {
        $request = $this->begin();
        $verified = $this->enrollment->confirm('42', $request->token, $this->authenticator->attestation($request), 'browser');
        self::assertNotNull($verified);
        $this->credentials->items[$verified->id] = $verified;
        $newRequest = $this->begin();
        self::assertSame(B64::encodeUnpadded($verified->id), $newRequest->publicKey['excludeCredentials'][0]['id']);
        self::assertNull($this->enrollment->confirm('42', $newRequest->token, $this->authenticator->attestation($newRequest), 'browser'));

        $this->credentials->items[$verified->id] = new StoredCredential($verified->id, 'other-user', $verified->record);
        $newRequest = $this->begin();
        self::assertEmpty($newRequest->publicKey['excludeCredentials'] ?? []);
        self::assertNull($this->enrollment->confirm('42', $newRequest->token, $this->authenticator->attestation($newRequest), 'browser'));
    }

    public function testAccountChangesInvalidatePendingRegistration(): void
    {
        foreach (['disabled', 'password', 'totp', 'deleted'] as $change) {
            $user = $this->addUser();
            $request = $this->begin();
            $this->users->items['42'] = match ($change) {
                'disabled' => new User('42', 'alice', $user->passwordHash, disabled: true),
                'password' => new User('42', 'alice', 'new-password-hash'),
                default => new User('42', 'alice', $user->passwordHash, totpSecret: 'NEWSECRET'),
            };
            if ($change === 'deleted') unset($this->users->items['42']);
            self::assertNull($this->enrollment->confirm('42', $request->token, $this->authenticator->attestation($request), 'browser'));
        }
    }

    public function testUnknownAndDisabledUsersCannotBegin(): void
    {
        foreach ([null, new User('42', 'alice', null, disabled: true)] as $user) {
            $this->users->items = $user === null ? [] : ['42' => $user];
            try {
                $this->begin();
                self::fail('Ineligible user started registration.');
            } catch (\DomainException $error) {
                self::assertSame('User is not eligible for passkey enrollment.', $error->getMessage());
            }
        }
    }

    public function testInvalidConfirmationsAreLimitedAcrossNewChallenges(): void
    {
        for ($i = 0; $i < 3; $i++) {
            $request = $this->begin();
            self::assertNull($this->enrollment->confirm('42', $request->token, [], 'browser'));
        }
        $request = $this->begin();
        self::assertNull($this->enrollment->confirm('42', $request->token, $this->authenticator->attestation($request), 'browser'));
        $this->clock->timestamp += 60;
        $request = $this->begin();
        self::assertNotNull($this->enrollment->confirm('42', $request->token, $this->authenticator->attestation($request), 'browser'));
    }
}
