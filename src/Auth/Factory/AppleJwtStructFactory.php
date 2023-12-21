<?php declare(strict_types=1);

namespace Azimo\Apple\Auth\Factory;

use Azimo\Apple\Auth\Exception\MissingClaimException;
use Azimo\Apple\Auth\Struct\JwtPayload;
use Lcobucci\JWT\Token;

class AppleJwtStructFactory
{
    /**
     * @throws MissingClaimException
     */
    public function createJwtPayloadFromToken(Token $token): JwtPayload
    {
        $claims = $token->claims();

        return new JwtPayload(
            $claims->get('iss'),
            $claims->get('aud'),
            $claims->get('exp'),
            $claims->get('iat'),
            $claims->get('sub'),
            $claims->get('c_hash', ''),
            $claims->get('email', null),
            // For some reason Apple API returns boolean flag as a string
            $claims->get('email_verified', null) != null ? (string) $claims->get('email_verified', 'false') === 'true' : null,
            // For some reason Apple API returns boolean flag as a string
            $claims->get('is_private_email', null) != null ? (string) $claims->get('is_private_email', 'false') === 'true' : null,
            $claims->get('auth_time'),
            $claims->get('nonce_supported', false),
            $claims->get('nonce')
        );
    }
}
