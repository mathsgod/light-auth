<?php
declare(strict_types=1);
namespace Light\Auth\Tests;

use Light\Auth\Contract\CredentialRepository;
use Light\Auth\Status;
use Light\Auth\WebAuthn\{AssertionRequest, Serializer, StoredCredential, WebAuthnService};
use ParagonIE\ConstantTime\Base64UrlSafe as B64;
use PHPUnit\Framework\Attributes\DataProvider;
use Symfony\Component\Uid\Uuid;
use Webauthn\{CredentialRecord, PublicKeyCredentialRequestOptions};
use Webauthn\TrustPath\EmptyTrustPath;

final class WebAuthnTest extends AuthTestCase
{
    private WebAuthnService $passkeys;
    private CredentialRepository $credentials;
    private \OpenSSLAsymmetricKey $key;
    private string $credentialId;

    protected function setUp(): void
    {
        parent::setUp();
        $this->addUser(mfa: true);
        $this->key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        $details = openssl_pkey_get_details($this->key);
        // COSE EC2 public key: {1: 2, 3: -7, -1: 1, -2: x, -3: y}.
        $publicKey = "\xa5\x01\x02\x03\x26\x20\x01\x21\x58\x20" . $details['ec']['x'] . "\x22\x58\x20" . $details['ec']['y'];
        $this->credentialId = random_bytes(32);
        $record = new CredentialRecord($this->credentialId, 'public-key', ['internal'], 'none', EmptyTrustPath::create(), Uuid::v4(), $publicKey, '42', 1);
        $stored = new StoredCredential($this->credentialId, '42', Serializer::create()->serialize($record, 'json'));
        $this->credentials = new class($stored) implements CredentialRepository {
            public function __construct(public StoredCredential $stored) {}
            public function find(string $credentialId): ?StoredCredential { return $credentialId === $this->stored->id ? $this->stored : null; }
            public function replace(StoredCredential $previous, string $updatedRecord): bool
            {
                if ($this->stored->record !== $previous->record) return false;
                $this->stored = new StoredCredential($previous->id, $previous->userId, $updatedRecord);
                return true;
            }
        };
        $this->passkeys = new WebAuthnService($this->users, $this->credentials, $this->challenges, $this->limiter, 'example.test', ['https://example.test']);
    }

    /** @return array<string, mixed> */
    private function assertion(AssertionRequest $request, string $mutation = ''): array
    {
        $clientData = json_encode([
            'type' => 'webauthn.get',
            'challenge' => $mutation === 'challenge' ? B64::encodeUnpadded(random_bytes(32)) : $request->publicKey['challenge'],
            'origin' => $mutation === 'origin' ? 'https://evil.example.test' : 'https://example.test',
            'crossOrigin' => false,
        ], JSON_THROW_ON_ERROR);
        $rp = $mutation === 'rp' ? 'evil.test' : 'example.test';
        $flags = $mutation === 'uv' ? "\x01" : "\x05";
        $authData = hash('sha256', $rp, true) . $flags . pack('N', $mutation === 'counter' ? 1 : 2);
        openssl_sign($authData . hash('sha256', $clientData, true), $signature, $this->key, OPENSSL_ALGO_SHA256);
        if ($mutation === 'signature') $signature = str_repeat('x', strlen($signature));
        return [
            'id' => B64::encodeUnpadded($this->credentialId),
            'rawId' => B64::encodeUnpadded($this->credentialId),
            'type' => 'public-key',
            'response' => [
                'authenticatorData' => B64::encodeUnpadded($authData),
                'clientDataJSON' => B64::encodeUnpadded($clientData),
                'signature' => B64::encodeUnpadded($signature),
                'userHandle' => $mutation === 'handle' ? B64::encodeUnpadded('other') : B64::encodeUnpadded('42'),
            ],
        ];
    }

    public function testSignedPasskeyAuthenticatesAndUpdatesCounterWithoutPasswordOrTotp(): void
    {
        $request = $this->passkeys->begin('browser');
        self::assertSame('required', $request->publicKey['userVerification']);
        self::assertEmpty($request->publicKey['allowCredentials'] ?? []);
        $assertion = $this->assertion($request);
        $result = $this->passkeys->complete($request->token, $assertion, 'ip', 'browser');
        self::assertSame(Status::Authenticated, $result->status);
        self::assertSame('42', $result->userId);
        $stored = Serializer::create()->deserialize($this->credentials->stored->record, CredentialRecord::class, 'json');
        self::assertSame(2, $stored->counter);
        self::assertSame(Status::InvalidCredentials, $this->passkeys->complete($request->token, $assertion, 'ip', 'browser')->status);
    }

    public static function invalidAssertions(): iterable
    {
        foreach (['challenge', 'origin', 'signature', 'rp', 'uv', 'handle', 'counter'] as $value) yield $value => [$value];
    }

    #[DataProvider('invalidAssertions')]
    public function testRejectsInvalidSignedAssertions(string $mutation): void
    {
        $request = $this->passkeys->begin('browser');
        self::assertSame(Status::InvalidCredentials, $this->passkeys->complete($request->token, $this->assertion($request, $mutation), 'ip', 'browser')->status);
        $stored = Serializer::create()->deserialize($this->credentials->stored->record, CredentialRecord::class, 'json');
        self::assertSame(1, $stored->counter);
    }

    public function testExpiredBoundAndMalformedChallengesCannotAuthenticate(): void
    {
        $request = $this->passkeys->begin('browser');
        self::assertSame(Status::InvalidCredentials, $this->passkeys->complete($request->token, $this->assertion($request), 'ip', 'other-browser')->status);
        $this->clock->timestamp += 30;
        self::assertSame(Status::InvalidCredentials, $this->passkeys->complete($request->token, $this->assertion($request), 'ip', 'browser')->status);
        $request = $this->passkeys->begin('browser');
        self::assertSame(Status::InvalidCredentials, $this->passkeys->complete($request->token, [], 'ip', 'browser')->status);
    }

    public function testRejectsUntrustedOriginConfiguration(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new WebAuthnService($this->users, $this->credentials, $this->challenges, $this->limiter, 'example.test', ['https://evil.test']);
    }
}
