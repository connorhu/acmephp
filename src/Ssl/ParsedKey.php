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
 * Represent the content of a parsed key.
 *
 * @see openssl_pkey_get_details
 *
 * @author Titouan Galopin <galopintitouan@gmail.com>
 */
class ParsedKey
{
    /** @var Key */
    private $source;

    /** @var string */
    private $key;

    /** @var int */
    private $bits;

    /** @var int */
    private $type;

    private const VALID_TYPES = [OPENSSL_KEYTYPE_RSA, OPENSSL_KEYTYPE_DSA, OPENSSL_KEYTYPE_DH, OPENSSL_KEYTYPE_EC];

    /** @var array */
    private $details;

    public function __construct(Key $source, string $key, int $bits, int $type, array $details = [])
    {
        if (empty($key)) {
            throw new \InvalidArgumentException(sprintf('%s::$key expected a non empty string. Got: "%s"', __CLASS__, $key));
        }

        if (!\in_array($type, self::VALID_TYPES)) {
            $message = sprintf('%s::$type expected one of: %s. Got: "%s"', __CLASS__, implode(', ', self::VALID_TYPES), $type);
            throw new \InvalidArgumentException($message);
        }

        $this->source = $source;
        $this->key = $key;
        $this->bits = $bits;
        $this->type = $type;
        $this->details = $details;
    }

    public function getSource(): Key
    {
        return $this->source;
    }

    public function getKey(): string
    {
        return $this->key;
    }

    public function getBits(): int
    {
        return $this->bits;
    }

    public function getType(): int
    {
        return $this->type;
    }

    public function getDetails(): array
    {
        return $this->details;
    }

    public function hasDetail(string $name): bool
    {
        return isset($this->details[$name]);
    }

    public function getDetail(string $name)
    {
        if (!isset($this->details[$name])) {
            $message = sprintf('ParsedKey::getDetail() expected one of: "%s". Got: "%s"', implode(', ', array_keys($this->details)), $name);
            throw new \InvalidArgumentException($message);
        }

        return $this->details[$name];
    }
}
