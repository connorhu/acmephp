<?php

/*
 * This file is part of the Acme PHP project.
 *
 * (c) Titouan Galopin <galopintitouan@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace AcmePhp\Core\Challenge\Http;

use AcmePhp\Core\Challenge\SolverInterface;
use AcmePhp\Core\Challenge\ValidatorInterface;
use AcmePhp\Core\Protocol\AuthorizationChallenge;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;

/**
 * Validator for HTTP challenges.
 *
 * @author Jérémy Derussé <jeremy@derusse.com>
 */
class HttpValidator implements ValidatorInterface
{
    /**
     * @var HttpDataExtractor
     */
    private $extractor;

    /**
     * @var ClientInterface
     */
    private ClientInterface $client;

    /**
     * @var RequestFactoryInterface
     */
    private RequestFactoryInterface $requestFactory;

    public function __construct(ClientInterface $client, RequestFactoryInterface $requestFactory, HttpDataExtractor $extractor = null)
    {
        $this->extractor = $extractor ?: new HttpDataExtractor();
        $this->client = $client;
        $this->requestFactory = $requestFactory;
    }

    /**
     * {@inheritdoc}
     */
    public function supports(AuthorizationChallenge $authorizationChallenge, SolverInterface $solver): bool
    {
        return 'http-01' === $authorizationChallenge->getType() && !$solver instanceof MockServerHttpSolver;
    }

    /**
     * {@inheritdoc}
     */
    public function isValid(AuthorizationChallenge $authorizationChallenge, SolverInterface $solver): bool
    {
        $checkUrl = $this->extractor->getCheckUrl($authorizationChallenge);
        $checkContent = $this->extractor->getCheckContent($authorizationChallenge);

        try {
            $request = $this->requestFactory->createRequest('GET', $checkUrl);
            $response = $this->client->sendRequest($request);
            return $checkContent === trim($response->getBody()->getContents());
        } catch (ClientExceptionInterface $e) {
            return false;
        }
    }
}
