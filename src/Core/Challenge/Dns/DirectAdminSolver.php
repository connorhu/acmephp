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
use AcmePhp\Core\Exception\Challenge\Dns\DirectAdminDnsControlException;
use AcmePhp\Core\Exception\Challenge\Dns\ZoneNotManagedByDirectAdminException;
use AcmePhp\Core\Protocol\AuthorizationChallenge;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Log\LoggerAwareTrait;
use Psr\Log\NullLogger;

/**
 * ACME DNS solver with automate configuration of a DirectAdmin managed DNS.
 *
 * @author Karoly Gossler <connor@connor.hu>
 */
class DirectAdminSolver implements MultipleChallengesSolverInterface, ConfigurableServiceInterface
{
    use LoggerAwareTrait;

    /**
     * @var DnsDataExtractor
     */
    private DnsDataExtractor $extractor;

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
    private array $cacheZones;

    /**
     * @var string
     */
    private string $host;

    /**
     * @var string
     */
    private string $username;

    /**
     * @var string
     */
    private string $password;

    /**
     * @var array<string>
     */
    private array $domains;

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
        if (!isset($config['host'])) {
            throw new \InvalidArgumentException('Config Key "host" is required');
        }
        if (!isset($config['username'])) {
            throw new \InvalidArgumentException('Config Key "username" is required');
        }
        if (!isset($config['password'])) {
            throw new \InvalidArgumentException('Config Key "password" is required');
        }

        $this->host = $config['host'];
        $this->username = $config['username'];
        $this->password = $config['password'];

        $this->domains = [];
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

    private function getDirectAdminUrl(): string
    {
        $parts = parse_url($this->host);
        $port = isset($parts['port']) ? ':'.$parts['port'] : '';

        // path?

        return $parts['scheme'].'://'.$this->username.':'.$this->password.'@'.$parts['host'].$port;
    }

    private function getShowDomainsEndpoint(): string
    {
        return $this->getDirectAdminUrl().'/CMD_API_SHOW_DOMAINS';
    }

    private function getDnsControlEndpoint(): string
    {
        return $this->getDirectAdminUrl().'/CMD_API_DNS_CONTROL';
    }

    /**
     * {@inheritdoc}
     * @throws ZoneNotManagedByDirectAdminException
     */
    public function solveAll(array $authorizationChallenges): void
    {
        foreach ($authorizationChallenges as $authorizationChallenge) {
            if (!$authorizationChallenge instanceof AuthorizationChallenge) {
                throw new \InvalidArgumentException('solveAll::$authorizationChallenges should array of "%s"', AuthorizationChallenge::class);
            }
        }

        $this->fetchDomainList();

        foreach ($authorizationChallenges as $authorizationChallenge) {
            $recordName = $this->extractor->getRecordName($authorizationChallenge);
            $recordValue = $this->extractor->getRecordValue($authorizationChallenge);
            $baseDomain = $this->getBaseDomain($recordName);

            if (!in_array($baseDomain, $this->domains)) {
                throw new ZoneNotManagedByDirectAdminException($baseDomain);
            }

            $this->addTextRecord($baseDomain, $recordName, $recordValue);
        }
    }

    /**
     * @throws \Psr\Http\Client\ClientExceptionInterface
     */
    private function sendRequest(string $endpoint, ?string $query = null)
    {
        $uri = $endpoint;

        if ($query !== null) {
            $uri .= '?'.$query;
        }

        $request = $this->requestFactory->createRequest('POST', $uri);
        $response = $this->client->sendRequest($request);

        $content = $response->getBody()->getContents();
        parse_str($content, $resultFields);

        return $resultFields;
    }

    private function addTextRecord(string $domain, string $zoneName, string $recordValue)
    {
        $values = [
            'domain' => $domain,
            'action' => 'add',
            'type' => 'TXT',
            'name' => $zoneName,
            'value' => '"'.$recordValue.'"',
        ];

        $result = $this->sendRequest($this->getDnsControlEndpoint(), http_build_query($values));

        if ($result['error'] !== '0') {
            throw new DirectAdminDnsControlException($result['error']);
        }

        return;
    }

    private function removeTextRecord(string $domain, string $zoneName, string $recordValue)
    {
        $values = [
            'domain' => $domain,
            'action' => 'select',
            'txtrecs0' => urlencode('name='. $zoneName.'&value="'.$recordValue.'"'),
        ];

        $result = $this->sendRequest($this->getDnsControlEndpoint(), http_build_query($values));

        if ($result['error'] !== '0') {
            throw new DirectAdminDnsControlException($result['error']);
        }

        return;
    }

    /**
     * @throws \Psr\Http\Client\ClientExceptionInterface
     */
    private function fetchDomainList()
    {
        $result = $this->sendRequest($this->getShowDomainsEndpoint());

        $this->domains = $result['list'];
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
     * @throws DirectAdminDnsControlException
     */
    public function cleanupAll(array $authorizationChallenges)
    {
        foreach ($authorizationChallenges as $authorizationChallenge) {
            if (!$authorizationChallenge instanceof AuthorizationChallenge) {
                throw new \InvalidArgumentException('cleanupAll::$authorizationChallenges should array of "%s"', AuthorizationChallenge::class);
            }
        }

        foreach ($authorizationChallenges as $authorizationChallenge) {
            $recordName = $this->extractor->getRecordName($authorizationChallenge);
            $recordValue = $this->extractor->getRecordValue($authorizationChallenge);
            $baseDomain = $this->getBaseDomain($recordName);

            if (!in_array($baseDomain, $this->domains)) {
                throw new ZoneNotManagedByDirectAdminException($baseDomain);
            }

            $this->removeTextRecord($baseDomain, $recordName, $recordValue);
        }
    }

    protected function getBaseDomain(string $domain): string
    {
        return substr(\implode('.', \array_slice(\explode('.', $domain), -3)), 0, -1);
    }
}
