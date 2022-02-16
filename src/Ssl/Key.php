<?php

/*
 * This file is part of the Acme PHP project.
 *
 * (c) Titouan Galopin <galopintitouan@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace AcmePhp\Ssl;

/**
 * Represent a SSL key.
 *
 * @author Jérémy Derussé <jeremy@derusse.com>
 */
abstract class Key
{
    /** @var string */
    protected $keyPEM;

    public function __construct(string $keyPEM)
    {
        if (empty($keyPEM)) {
            throw new \InvalidArgumentException(sprintf('%s::$keyPEM expected a non empty string. Got: "%s"', __CLASS__, $keyPEM));
        }

        $this->keyPEM = $keyPEM;
    }

    public function getPEM(): string
    {
        return $this->keyPEM;
    }

    public function getDER(): string
    {
        $lines = explode("\n", trim($this->keyPEM));
        unset($lines[\count($lines) - 1]);
        unset($lines[0]);
        $result = implode('', $lines);

        return base64_decode($result);
    }

    /**
     * @deprecated 
     * @return resource
     */
    abstract public function getResource();

    /**
     * @return \OpenSSLAsymmetricKey
     */
    abstract public function getAsymmetricKey(): \OpenSSLAsymmetricKey;
}
