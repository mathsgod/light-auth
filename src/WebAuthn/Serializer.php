<?php
declare(strict_types=1);
namespace Light\Auth\WebAuthn;
use Symfony\Component\Serializer\SerializerInterface;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
final class Serializer
{
    public static function create(): SerializerInterface
    {
        $manager = AttestationStatementSupportManager::create();
        $manager->add(NoneAttestationStatementSupport::create());
        return (new WebauthnSerializerFactory($manager))->create();
    }
}
