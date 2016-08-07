<?php
namespace Core\Security\Token;

/**
 * StorageToken.php
 *
 * @author Michael "Tekkla" Zorn <tekkla@tekkla.de>
 * @copyright 2016
 * @license MIT
 */
class StorageToken extends AbstractToken
{

    /**
     *
     * @var array
     */
    protected $storage;

    /**
     *
     * @var string
     */
    protected $key = 'session_token';

    /**
     * Sets a storage array reference where the token under the set key should be stored
     *
     * @param array $storage
     *            The storage array as reference. This can be $_SESSION for example.
     */
    public function setStorage(array &$storage)
    {
        $this->storage = $storage;
    }

    /**
     * Sets storage token key
     *
     * @param string $key
     */
    public function setKey(string $key)
    {
        $this->key = $key;
    }

    /**
     * Returns storage token key
     *
     * @return string
     */
    public function getKey(): string
    {
        return $this->key;
    }

    public function generateRandomToken(): string
    {
        $token = parent::generateRandomToken();

        $this->storage[$this->key] = $token;

        return $token;
    }
}

