<?php
declare(strict_types=1);

namespace Light\Auth\WebAuthn;

use Webauthn\CeremonyStep\CeremonyStepManagerFactory;

final class RelyingParty
{
    /** @param list<string> $allowedOrigins */
    public static function factory(string $rpId, array $allowedOrigins): CeremonyStepManagerFactory
    {
        if ($rpId === '' || $allowedOrigins === []) throw new \InvalidArgumentException('RP ID and exact allowed origins are required.');
        foreach ($allowedOrigins as $origin) {
            $parts = parse_url($origin);
            if (!is_array($parts) || !isset($parts['host'], $parts['scheme']) ||
                isset($parts['user']) || isset($parts['pass']) || isset($parts['query']) || isset($parts['fragment']) || isset($parts['path']) ||
                ($parts['host'] !== $rpId && !str_ends_with($parts['host'], '.' . $rpId)) ||
                ($parts['scheme'] !== 'https' && !($parts['scheme'] === 'http' && $parts['host'] === 'localhost' && $rpId === 'localhost'))) {
                throw new \InvalidArgumentException('Origins must be exact HTTPS origins within the RP ID (HTTP localhost allowed).');
            }
        }
        $factory = new CeremonyStepManagerFactory();
        $factory->setAllowedOrigins($allowedOrigins, false);
        return $factory;
    }
}
