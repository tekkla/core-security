<?php
namespace Core\Security\User;

use Core\Security\Token\ActivationToken;

/**
 * Activation.php
 *
 * @author Michael "Tekkla" Zorn <tekkla@tekkla.de>
 * @copyright 2016
 * @license MIT
 */
class Activation
{
    /**
     * Loads permissions for a given list of group ids
     *
     * @param array $groups
     *            Array of group ids to load the permissions for
     *
     * @param array $groups
     */

    /**
     * Returns user id for an activation key
     *
     * @param unknown $token
     * @return boolean
     */
    private function getUserIdByActivationKey($key)
    {

        // Lets try to find the user id in our activation token table
        $token = new ActivationToken($this->db);
        $result = $token->getActivationTokenDataFromKey($key);

        if (empty($result)) {
            return false;
        }

        // Do not trust any result that has more then one entry!!!
        if (count($result) > 1) {

            $this->logger->warning('There is more than one user with identical activationkey!');

            Throw new UserException('There is more than one user with identical activationkey!');
        }

        return $result[0]['id_user'];
    }

    public function denyActivation($key)
    {
        // Get tokendate from db
        $id_user = $this->getUserIdByActivationKey($key);

        // Nothings to do when already removed
        if (empty($id_user)) {
            return false;
        }

        // Remove the user and the token
        $this->deleteUser($id_user);
        $this->token->deleteActivationTokenByUserId($id_user);

        return true;
    }

    /**
     * Actives user by using a key
     *
     * @param string $key
     *            Key to use for activation
     */
    public function activateUser($key)
    {

        // Get tokendate from db
        $tokenhandler = new ActivationToken($this->db);
        $tokenhandler->setSelectorTokenString($key);

        // Store the current to extracted from selector:token string ($key)
        $token_from_key = $tokenhandler->getToken();

        // Load the tokendata by using the selector from selector:token string ($key)
        $tokenhandler->loadTokenData();

        // Get user id
        $id_user = $tokenhandler->getUserId();

        // No user id means the activation must fail
        if (empty($id_user)) {
            return false;
        }

        // Get the token loaded from db via selector from selector:token string ($key)
        $token_from_db = $tokenhandler->getToken();

        // Matching hashes?
        if (!hash_equals($token_from_key, $token_from_db)) {
            return false;
        }

        // Activate user
        $this->db->qb([
            'table' => 'core_users',
            'method' => 'UPDATE',
            'fields' => 'state',
            'filter' => 'id_user=:id_user',
            'params' => [
                ':state' => 0,
                ':id_user' => $id_user
            ]
        ], true);

        // and delete the token of this user
        $tokenhandler->deleteActivationTokenByUserId($id_user);

        // And finally return user id
        return $id_user;
    }

}

