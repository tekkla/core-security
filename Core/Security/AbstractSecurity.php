<?php
namespace Core\Security;

use Psr\Log\LoggerInterface;

/**
 * AbstractSecurity.php
 *
 * @author Michael "Tekkla" Zorn <tekkla@tekkla.de>
 * @copyright 2016
 * @license MIT
 */
abstract class AbstractSecurity
{
    /**
     *
     * @var LoggerInterface
     */
    protected $logger;

    /**
     * Injects a psr/log compatible logger service
     *
     * @param LoggerInterface $logger
     */
    public function setLogger(LoggerInterface $logger)
    {
        $this->logger = $logger;
    }
}