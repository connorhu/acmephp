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

use AcmePhp\Ssl\Exception\CertificateFormatException;

/**
 * Represent a Certificate.
 *
 * @author Jérémy Derussé <jeremy@derusse.com>
 */
class Certificate
{
    /** @var string */
    private $certificatePEM;

    /** @var Certificate */
    private $issuerCertificate;

    public function __construct(string $certificatePEM, self $issuerCertificate = null)
    {
        if (empty($certificatePEM)) {
            throw new \InvalidArgumentException(sprintf('%s::$certificatePEM expected a non empty string. Got: "%s"', __CLASS__, $certificatePEM));
        }

        $this->certificatePEM = $certificatePEM;
        $this->issuerCertificate = $issuerCertificate;
    }

    /**
     * @return array<Certificate>
     */
    public function getIssuerChain(): array
    {
        $chain = [];
        $issuerCertificate = $this->getIssuerCertificate();

        while (null !== $issuerCertificate) {
            $chain[] = $issuerCertificate;
            $issuerCertificate = $issuerCertificate->getIssuerCertificate();
        }

        return $chain;
    }

    public function getPEM(): string
    {
        return $this->certificatePEM;
    }

    public function getIssuerCertificate(): ?self
    {
        return $this->issuerCertificate;
    }

    /**
     * @deprecated
     * @return resource
     */
    public function getPublicKeyResource()
    {
        return $this->doGetPublicKey();
    }

    private function doGetPublicKey()
    {
        if (!$resource = openssl_pkey_get_public($this->certificatePEM)) {
            throw new CertificateFormatException(sprintf('Failed to convert certificate into public key resource: %s', openssl_error_string()));
        }

        return $resource;
    }

    /**
     * @return \OpenSSLAsymmetricKey
     */
    public function getAsymmetricPublicKey(): \OpenSSLAsymmetricKey
    {
        if (PHP_VERSION_ID < 80000) {
            throw new \BadMethodCallException('This method available only over php version 8.0');
        }

        /** @var \OpenSSLAsymmetricKey $publicKey */
        /** @noinspection PhpUnnecessaryLocalVariableInspection */
        $publicKey = $this->doGetPublicKey();

        return $publicKey;
    }

    public function getPublicKey(): PublicKey
    {
        return new PublicKey(openssl_pkey_get_details($this->getPublicKeyResource())['key']);
    }
}
