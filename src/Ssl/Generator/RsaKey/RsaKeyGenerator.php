<?php

/*
 * This file is part of the Acme PHP project.
 *
 * (c) Titouan Galopin <galopintitouan@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace AcmePhp\Ssl\Generator\RsaKey;

use AcmePhp\Ssl\Generator\KeyOption;
use AcmePhp\Ssl\Generator\OpensslPrivateKeyGeneratorTrait;
use AcmePhp\Ssl\Generator\PrivateKeyGeneratorInterface;
use AcmePhp\Ssl\PrivateKey;

/**
 * Generate random RSA private key using OpenSSL.
 *
 * @author Jérémy Derussé <jeremy@derusse.com>
 */
class RsaKeyGenerator implements PrivateKeyGeneratorInterface
{
    use OpensslPrivateKeyGeneratorTrait;

    public function generatePrivateKey(KeyOption $keyOption): PrivateKey
    {
        if (!$keyOption instanceof RsaKeyOption) {
            $message = sprintf('%s::$keyOption expected an instance of %s. Got: %s', __METHOD__, RsaKeyOption::class, \get_class($keyOption));
            throw new \InvalidArgumentException($message);
        }

        return $this->generatePrivateKeyFromOpensslOptions([
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
            'private_key_bits' => $keyOption->getBits(),
        ]);
    }

    public function supportsKeyOption(KeyOption $keyOption): bool
    {
        return $keyOption instanceof RsaKeyOption;
    }
}
