<?php

/*
 * This file is part of the Acme PHP project.
 *
 * (c) Titouan Galopin <galopintitouan@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace AcmePhp\Core\Filesystem\Adapter;

use AcmePhp\Core\Filesystem\FilesystemFactoryInterface;
use AcmePhp\Core\Filesystem\FilesystemInterface;
use League\Flysystem\Adapter\Local;
use League\Flysystem\Filesystem;

class FlysystemLocalFactory implements FilesystemFactoryInterface
{
    /**
     * {@inheritdoc}
     */
    public function create(array $config): FilesystemInterface
    {
        if (!isset($config['root'])) {
            throw new \InvalidArgumentException('create::$config expected an array with the key root.');
        }

        return new FlysystemAdapter(new Filesystem(new Local($config['root'])));
    }
}
