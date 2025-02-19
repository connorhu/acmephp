<?php

/*
 * This file is part of the Acme PHP project.
 *
 * (c) Titouan Galopin <galopintitouan@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace AcmePhp\Core\Tests\Challenge\Http;

use AcmePhp\Core\Challenge\Http\HttpDataExtractor;
use AcmePhp\Core\Protocol\AuthorizationChallenge;
use PHPUnit\Framework\TestCase;

class HttpDataExtractorTest extends TestCase
{
    public function testGetCheckUrl()
    {
        $domain = 'foo.com';
        $token = 'randomToken';

        $stubChallenge = $this->prophesize(AuthorizationChallenge::class);

        $extractor = new HttpDataExtractor();

        $stubChallenge->getDomain()->willReturn($domain);
        $stubChallenge->getToken()->willReturn($token);

        $this->assertEquals(
            'http://'.$domain.'/.well-known/acme-challenge/'.$token,
            $extractor->getCheckUrl($stubChallenge->reveal())
        );
    }

    public function testGetCheckContent()
    {
        $payload = 'randomPayload';

        $stubChallenge = $this->prophesize(AuthorizationChallenge::class);

        $extractor = new HttpDataExtractor();

        $stubChallenge->getPayload()->willReturn($payload);

        $this->assertEquals($payload, $extractor->getCheckContent($stubChallenge->reveal()));
    }
}
