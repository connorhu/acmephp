<?php

/*
 * This file is part of the Acme PHP project.
 *
 * (c) Titouan Galopin <galopintitouan@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace AcmePhp\Core\Challenge\Dns;

use AcmePhp\Core\Challenge\ConfigurableServiceInterface;
use AcmePhp\Core\Challenge\MultipleChallengesSolverInterface;
use AcmePhp\Core\Protocol\AuthorizationChallenge;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Log\LoggerAwareTrait;
use Psr\Log\NullLogger;

/**
 * ACME DNS solver with automate configuration of a Gandi.Net.
 *
 * @author Alexander Obuhovich <aik.bold@gmail.com>
 */
class GandiSolver implements MultipleChallengesSolverInterface, ConfigurableServiceInterface
{
    use LoggerAwareTrait;

    /**
     * @var DnsDataExtractor
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

    /**
     * @var StreamFactoryInterface
     */
    private StreamFactoryInterface $streamFactory;

    /**
     * @var array
     */
    private $cacheZones;

    /**
     * @var string
     */
    private $apiKey;

    public function __construct(ClientInterface $client, RequestFactoryInterface $requestFactory, StreamFactoryInterface $streamFactory, DnsDataExtractor $extractor = null)
    {
        $this->extractor = $extractor ?: new DnsDataExtractor();
        $this->client = $client;
        $this->requestFactory = $requestFactory;
        $this->streamFactory = $streamFactory;
        $this->logger = new NullLogger();
    }

    /**
     * Configure the service with a set of configuration.
     */
    public function configure(array $config)
    {
        $this->apiKey = $config['api_key'];
    }

    /**
     * {@inheritdoc}
     */
    public function supports(AuthorizationChallenge $authorizationChallenge): bool
    {
        return 'dns-01' === $authorizationChallenge->getType();
    }

    /**
     * {@inheritdoc}
     */
    public function solve(AuthorizationChallenge $authorizationChallenge)
    {
        $this->solveAll([$authorizationChallenge]);
    }

    /**
     * {@inheritdoc}
     */
    public function solveAll(array $authorizationChallenges): void
    {
        foreach ($authorizationChallenges as $authorizationChallenge) {
            if (!$authorizationChallenge instanceof AuthorizationChallenge::class) {
                throw new \InvalidArgumentException('solveAll::$authorizationChallenges should array of "%s"', AuthorizationChallenge::class);
            }
        }

        foreach ($authorizationChallenges as $authorizationChallenge) {
            $topLevelDomain = $this->getTopLevelDomain($authorizationChallenge->getDomain());
            $recordName = $this->extractor->getRecordName($authorizationChallenge);
            $recordValue = $this->extractor->getRecordValue($authorizationChallenge);

            $subDomain = \str_replace('.'.$topLevelDomain.'.', '', $recordName);

            $url = 'https://dns.api.gandi.net/api/v5/domains/'.$topLevelDomain.'/records/'.$subDomain.'/TXT';
            $jsonContent = json_encode([
                'rrset_type' => 'TXT',
                'rrset_ttl' => 600,
                'rrset_name' => $subDomain,
                'rrset_values' => [$recordValue],
            ]);

            $request = $this->requestFactory->createRequest('PUT', $url);
            $request->withHeader('X-Api-Key', $this->apiKey);
            $request->withBody($this->streamFactory->createStream($jsonContent));

            $this->client->sendRequest($request);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function cleanup(AuthorizationChallenge $authorizationChallenge)
    {
        $this->cleanupAll([$authorizationChallenge]);
    }

    /**
     * {@inheritdoc}
     */
    public function cleanupAll(array $authorizationChallenges)
    {
        foreach ($authorizationChallenges as $authorizationChallenge) {
            if (!$authorizationChallenge instanceof AuthorizationChallenge::class) {
                throw new \InvalidArgumentException('cleanupAll::$authorizationChallenges should array of "%s"', AuthorizationChallenge::class);
            }
        }

        foreach ($authorizationChallenges as $authorizationChallenge) {
            $topLevelDomain = $this->getTopLevelDomain($authorizationChallenge->getDomain());
            $recordName = $this->extractor->getRecordName($authorizationChallenge);

            $subDomain = \str_replace('.'.$topLevelDomain.'.', '', $recordName);
            $url = 'https://dns.api.gandi.net/api/v5/domains/'.$topLevelDomain.'/records/'.$subDomain.'/TXT';
            $request = $this->requestFactory->createRequest('DELETE', $url);
            $request->withHeader('X-Api-Key', $this->apiKey);

            $this->client->sendRequest($request);
        }
    }

    protected function getTopLevelDomain(string $domain): string
    {
        return \implode('.', \array_slice(\explode('.', $domain), -2));
    }
}
