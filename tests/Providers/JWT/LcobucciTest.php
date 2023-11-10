<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Fluent\JWTAuth\Test\Providers\JWT;

use Fluent\JWTAuth\Exceptions\JWTException;
use Fluent\JWTAuth\Exceptions\TokenInvalidException;
use Fluent\JWTAuth\Providers\JWT\Lcobucci;
use Fluent\JWTAuth\Test\AbstractTestCase;

class LcobucciTest extends AbstractTestCase
{
    /**
     * @var \Fluent\JWTAuth\Providers\JWT\Namshi
     */
    protected $provider;

    public function setUp(): void
    {
        parent::setUp();
    }

    /** @test */
    public function it_should_return_the_token_when_passing_a_valid_payload_to_encode()
    {
        $payload = ['sub' => 1, 'exp' => $this->testNowTimestamp + 3600, 'iat' => $this->testNowTimestamp, 'iss' => '/foo'];

        $token = $this->getProvider('secret-secret-secret-secret-secret', 'HS256')->encode($payload);

        $this->assertNotEmpty($token);
    }

    /** @test */
    public function it_should_throw_an_invalid_exception_when_the_payload_could_not_be_encoded()
    {
        $this->expectException(JWTException::class);
        $this->expectExceptionMessage('Could not create token:');

        $payload = ['sub' => 1, 'exp' => $this->testNowTimestamp, 'iat' => $this->testNowTimestamp, 'iss' => '/foo'];

        $this->getProvider('secret', 'HS256')->encode($payload);
    }

    /** @test */
    public function it_should_throw_an_invalid_exception_when_the_algorithm_is_not_supported()
    {
        $this->expectException(JWTException::class);
        $this->expectExceptionMessage('The given algorithm could not be found');

        $payload = ['sub' => 1, 'exp' => $this->testNowTimestamp, 'iat' => $this->testNowTimestamp, 'iss' => '/foo'];

        $this->getProvider('secret', 'AlgorithmWrong')->encode($payload);
    }

    /** @test */
    public function it_should_return_the_payload_when_passing_a_valid_token_to_decode()
    {
        $payload = ['sub' => '1', 'exp' => $this->testNowTimestamp + 3600, 'iat' => $this->testNowTimestamp, 'iss' => '/foo'];

        $token = $this->getProvider('secret-secret-secret-secret-secret', 'HS256')->encode($payload);

        $this->assertSame($payload, $this->getProvider('secret-secret-secret-secret-secret', 'HS256')->decode($token));
    }

    /** @test */
    public function it_should_throw_a_token_invalid_exception_when_the_token_could_not_be_decoded_due_to_a_bad_signature()
    {
        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessage('Could not decode token:');

        $this->getProvider('secret-secret-secret-secret-secret', 'HS256')->decode('foo.bar.baz');
    }

    /** @test */
    public function it_should_throw_a_token_invalid_exception_when_the_token_could_not_be_decoded()
    {
        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessage('Could not decode token:');

        $this->getProvider('secret', 'HS256')->decode('foo.bar.baz');
    }

    /** @test */
    public function it_should_generate_a_token_when_using_an_rsa_algorithm()
    {
        $provider = $this->getProvider(
            'does_not_matter',
            'RS256',
            ['private' => $this->getDummyPrivateKey(), 'public' => $this->getDummyPublicKey(), 'passphrase' => '']
        );

        $payload = ['sub' => 1, 'exp' => $this->testNowTimestamp + 3600, 'iat' => $this->testNowTimestamp, 'iss' => '/foo'];

        $token = $provider->encode($payload);

        $this->assertNotEmpty($token);
    }

    /** @test */
    public function it_should_throw_a_exception_when_the_algorithm_passed_is_invalid()
    {
        $this->expectException(JWTException::class);
        $this->expectExceptionMessage('The given algorithm could not be found');

        $this->getProvider('secret', 'AlgorithmWrong')->decode('foo.bar.baz');
    }

    /** @test */
    public function it_should_return_the_public_key()
    {
        $provider = $this->getProvider(
            'does_not_matter',
            'RS256',
            $keys = ['private' => $this->getDummyPrivateKey(), 'public' => $this->getDummyPublicKey(), 'passphrase' => '']
        );

        $this->assertSame($keys['public'], $provider->getPublicKey());
    }

    /** @test */
    public function it_should_return_the_keys()
    {
        $provider = $this->getProvider(
            'does_not_matter',
            'RS256',
            $keys = ['private' => $this->getDummyPrivateKey(), 'public' => $this->getDummyPublicKey(), 'passphrase' => '']
        );

        $this->assertSame($keys, $provider->getKeys());
    }

    public function getProvider($secret, $algo, array $keys = [])
    {
        return new Lcobucci($secret, $algo, $keys);
    }

    public function getDummyPrivateKey()
    {
        return __DIR__.'/../Keys/id_rsa';
    }

    public function getDummyPublicKey()
    {
        return __DIR__.'/../Keys/id_rsa.pub';
    }
}
