<?php

/**
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 * (c) Agung Sugiarto <me.agungsugiarto@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Fluent\JWTAuth\Providers\JWT;

use DateTimeImmutable;
use Exception;
use Fluent\JWTAuth\Contracts\Providers\JWTInterface;
use Fluent\JWTAuth\Exceptions\JWTException;
use Fluent\JWTAuth\Exceptions\TokenInvalidException;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Ecdsa;
use Lcobucci\JWT\Signer\Ecdsa\Sha256 as ES256;
use Lcobucci\JWT\Signer\Ecdsa\Sha384 as ES384;
use Lcobucci\JWT\Signer\Ecdsa\Sha512 as ES512;
use Lcobucci\JWT\Signer\Hmac\Sha256 as HS256;
use Lcobucci\JWT\Signer\Hmac\Sha384 as HS384;
use Lcobucci\JWT\Signer\Hmac\Sha512 as HS512;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa;
use Lcobucci\JWT\Signer\Rsa\Sha256 as RS256;
use Lcobucci\JWT\Signer\Rsa\Sha384 as RS384;
use Lcobucci\JWT\Signer\Rsa\Sha512 as RS512;
use Lcobucci\JWT\Token\RegisteredClaims;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Tightenco\Collect\Support\Collection;

use function array_key_exists;
use function is_object;

class Lcobucci extends Provider implements JWTInterface
{
    /**
     * The Configation instance.
     *
     * @var Configuration
     */
    protected $config;

    /**
     * Create the Lcobucci provider.
     *
     * @param  string  $secret
     * @param  string  $algo
     * @param  array  $keys
     * @return void
     */
    public function __construct(
        $secret,
        $algo,
        array $keys
    ) {
        parent::__construct($secret, $algo, $keys);

        $this->config = $this->getConfiguration();
    }

    /**
     * Signers that this provider supports.
     *
     * @var array
     */
    protected $signers = [
        'HS256' => HS256::class,
        'HS384' => HS384::class,
        'HS512' => HS512::class,
        'RS256' => RS256::class,
        'RS384' => RS384::class,
        'RS512' => RS512::class,
        'ES256' => ES256::class,
        'ES384' => ES384::class,
        'ES512' => ES512::class,
    ];

    /**
     * Create a JSON Web Token.
     *
     * @param  array  $payload
     * @throws JWTException
     * @return string
     */
    public function encode(array $payload)
    {
        $builder = $this->config->builder();

        try {
            foreach ($payload as $key => $value) {
                if (in_array($key, RegisteredClaims::ALL, true)) {
                    switch ($key) {
                        case RegisteredClaims::AUDIENCE:
                            $builder = $builder->permittedFor($value);
                            break;
                        case RegisteredClaims::EXPIRATION_TIME:
                            $builder = $builder->expiresAt(new DateTimeImmutable('@'.$value));
                            break;
                        case RegisteredClaims::ID:
                            $builder = $builder->identifiedBy($value);
                            break;
                        case RegisteredClaims::ISSUED_AT:
                            $builder = $builder->issuedAt(new DateTimeImmutable('@'.$value));
                            break;
                        case RegisteredClaims::ISSUER:
                            $builder = $builder->issuedBy($value);
                            break;
                        case RegisteredClaims::NOT_BEFORE:
                            $builder = $builder->canOnlyBeUsedAfter(new DateTimeImmutable('@'.$value));
                            break;
                        case RegisteredClaims::SUBJECT:
                            $builder = $builder->relatedTo($value);
                            break;
                    }
                } else {
                    $builder = $builder->withClaim($key, $value);
                }
            }

            $token = $builder->getToken($this->config->signer(), $this->config->signingKey());
        } catch (Exception $e) {
            throw new JWTException('Could not create token: '.$e->getMessage(), $e->getCode(), $e);
        }

        return $token->toString();
    }

    /**
     * Decode a JSON Web Token.
     *
     * @param  string  $token
     * @throws JWTException
     * @return array
     */
    public function decode($token)
    {
        try {
            $jwt = $this->config->parser()->parse($token);
        } catch (Exception $e) {
            throw new TokenInvalidException('Could not decode token: ' . $e->getMessage(), $e->getCode(), $e);
        }

        try {
            if (! $this->config->validator()->validate($jwt, ...$this->config->validationConstraints())) {
                throw new TokenInvalidException('Token Signature could not be verified.');
            }
        } catch (Exception $e) {
            throw new TokenInvalidException('Token Signature could not be verified: ' . $e->getMessage(), $e->getCode(), $e);
        }

        if ($jwt instanceof UnencryptedToken) {
            return (new Collection($jwt->claims()->all()))->map(function ($claim) {
                if ($claim instanceof DateTimeImmutable) {
                    return $claim->getTimestamp();
                }
                return is_object($claim) ? $claim->getValue() : $claim;
            })->toArray();
        } else {
            throw new TokenInvalidException('Token payload could not be loaded.');
        }
    }

    /**
     * Get the signer instance.
     *
     * @throws JWTException
     * @return Signer
     */
    protected function getSigner()
    {
        if (! array_key_exists($this->algo, $this->signers)) {
            throw new JWTException('The given algorithm could not be found');
        }

        return new $this->signers[$this->algo]();
    }

    /**
     * {@inheritdoc}
     */
    protected function isAsymmetric()
    {
        $signer = $this->getSigner();

        return $signer instanceof Rsa || $signer instanceof Ecdsa;
    }

    /**
     * {@inheritdoc}
     */
    protected function getSigningKey()
    {
        return $this->isAsymmetric()
            ? InMemory::file($this->getPrivateKey(), $this->getPassphrase())
            : InMemory::plainText($this->getSecret());
    }

    /**
     * {@inheritdoc}
     */
    protected function getVerificationKey()
    {
        return $this->isAsymmetric()
            ? InMemory::file($this->getPublicKey())
            : InMemory::plainText($this->getSecret());
    }

    /**
     * Get JWT Configuration instance
     *
     * @return Configuration
     */
    protected function getConfiguration() 
    {
        $config = $this->isAsymmetric()
            ? Configuration::forAsymmetricSigner($this->getSigner(), $this->getSigningKey(), $this->getVerificationKey())
            : Configuration::forSymmetricSigner($this->getSigner(), $this->getSigningKey());
        
        $config->setValidationConstraints(
            new SignedWith($config->signer(), $config->verificationKey())
        );

        return $config;
    }
}
