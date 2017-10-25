<?php
namespace Core\Security\Token;

/**
 * TokenInterface.php
 *
 * @author Michael "Tekkla" Zorn <tekkla@tekkla.de>
 * @copyright 2016
 * @license MIT
 */
interface TokenInterface
{

    /**
     * Sets token size eg length
     *
     * @param int $size
     */
    public function setSize(int $size);

    /**
     * Returns token size
     *
     * @return int
     */
    public function getSize(): int;

    /**
     * Generates a random token
     *
     * @return string
     */
    public function generateRandomToken(): string;
}

