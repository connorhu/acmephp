<?php

/*
 * This file is part of the Acme PHP project.
 *
 * (c) Titouan Galopin <galopintitouan@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace AcmePhp\Ssl\Generator\EcKey;

use AcmePhp\Ssl\Generator\KeyOption;
use AcmePhp\Ssl\Generator\OpensslPrivateKeyGeneratorTrait;
use AcmePhp\Ssl\Generator\PrivateKeyGeneratorInterface;
use AcmePhp\Ssl\PrivateKey;

/**
 * Generate random EC private key using OpenSSL.
 *
 * @author Jérémy Derussé <jeremy@derusse.com>
 */
class EcKeyGenerator implements PrivateKeyGeneratorInterface
{
    use OpensslPrivateKeyGeneratorTrait;

    public function generatePrivateKey(KeyOption $keyOption): PrivateKey
    {
        if (!$keyOption instanceof EcKeyOption) {
            $message = sprintf('%s::$keyOption expected an instance of %s. Got: %s', __METHOD__, EcKeyOption::class, \get_class($keyOption));
            throw new \InvalidArgumentException($message);
        }

        return $this->generatePrivateKeyFromOpensslOptions([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => $keyOption->getCurveName(),
        ]);
    }

    public function supportsKeyOption(KeyOption $keyOption): bool
    {
        return $keyOption instanceof EcKeyOption;
    }
}
