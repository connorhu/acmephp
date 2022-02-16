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

class EcKeyOption implements KeyOption
{
    /** @var string */
    private $curveName;

    public function __construct(string $curveName = 'secp384r1')
    {
        if (!\in_array($curveName, $curveNames = openssl_get_curve_names())) {
            $message = sprintf('The given curve "%s" is not supported. Available curves are: "%s"', $curveName, implode(', ', $curveNames));
            throw new \InvalidArgumentException($message);
        }

        $this->curveName = $curveName;
    }

    public function getCurveName(): string
    {
        return $this->curveName;
    }
}
