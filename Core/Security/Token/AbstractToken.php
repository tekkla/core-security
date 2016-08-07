<?php
namespace Core\Security\Token;

use Psr\Log\LoggerInterface;

/**
 * AbstractToken.php
 *
 * @author Michael "Tekkla" Zorn <tekkla@tekkla.de>
 * @copyright 2016
 * @license MIT
 */
abstract class AbstractToken implements TokenInterface
{

    /**
     *
     * @var int
     */
    protected $size = 32;

    /**
     *
     * @var int
     */
    protected $ttl;

    /**
     *
     * @var LoggerInterface
     */
    protected $logger;

    /**
     *
     * @var string
     */
    protected $token;

    /**
     * Sets token size eg length
     *
     * @param int $size
     */
    public function setSize(int $size)
    {
        $this->size = $size;
    }

    /**
     * Returns token size
     *
     * @return int
     */
    public function getSize(): int
    {
        return $this->size;
    }

    /**
     * Sets token TTL (in seconds)
     *
     * @param int $ttl
     *            TTL in seconds of this token
     */
    public function setTTL(int $ttl)
    {
        $this->ttl = $ttl;
    }

    /**
     *
     * @return int
     */
    public function getTTL(): int
    {
        return $this->ttl;
    }

    /**
     * Set logger object
     *
     * @param LoggerInterface $logger
     */
    public function setLogger(LoggerInterface $logger)
    {
        $this->logger = $logger;
    }

    /**
     * Returns the current token and creates a new token when there is no token present.
     *
     * @return string
     */
    public function getToken(): string
    {
        if (!isset($this->token)) {
            return $this->generateRandomToken();
        }

        return $this->token;
    }

    /**
     * Generates a random token
     *
     * @return string
     */
    public function generateRandomToken(): string
    {
        $this->token = function_exists('openssl_random_pseudo_bytes') ? openssl_random_pseudo_bytes($this->size) : mcrypt_create_iv($this->size);

        return $this->token;
    }
}

