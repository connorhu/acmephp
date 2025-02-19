<?php

/*
 * This file is part of the Acme PHP project.
 *
 * (c) Titouan Galopin <galopintitouan@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace AcmePhp\Core\Protocol;

/**
 * Represent a ACME resources directory.
 *
 * @author Titouan Galopin <galopintitouan@gmail.com>
 */
class ResourcesDirectory
{
    public const NEW_ACCOUNT = 'newAccount';
    public const NEW_ORDER = 'newOrder';
    public const NEW_NONCE = 'newNonce';
    public const REVOKE_CERT = 'revokeCert';

    /** @var array */
    private $serverResources;

    public function __construct(array $serverResources)
    {
        $this->serverResources = $serverResources;
    }

    /**
     * @return string[]
     */
    public static function getResourcesNames(): array
    {
        return [
            self::NEW_ACCOUNT,
            self::NEW_ORDER,
            self::NEW_NONCE,
            self::REVOKE_CERT,
        ];
    }

    /**
     * Find a resource URL.
     */
    public function getResourceUrl(string $resource): string
    {
        if (!isset($this->serverResources[$resource])) {
            $message = sprintf('Resource type "%s" is not supported by the ACME server (supported: "%s")', $resource, implode(', ', $this->serverResources));
            throw new \InvalidArgumentException($message);
        }

        return $this->serverResources[$resource];
    }
}
