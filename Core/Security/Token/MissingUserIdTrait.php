<?php
namespace Core\Security\Token;

/**
 * MissingUserIdTrait.php
 *
 * @author Michael "Tekkla" Zorn <tekkla@tekkla.de>
 * @copyright 2016
 * @license MIT
 */
trait MissingUserIdTrait {

    /**
     * Checks for a missing user id and either uses a logger to track missing id throws an exception
     *
     * @throws TokenException when no logger has been set
     *
     * @return bool
     */
    public function checkMissingUserId(): bool
    {
        if (!empty($this->id_user)) {
            return false;
        }

        $message = 'Can not perform action without set user id. Please set id via setIdUser() before calling this method.';

        if (!empty($this->logger)) {
            $this->logger->warning($message);
        }
        else {
            Throw new TokenException($message);
        }

        return true;
    }
}

