<?php
namespace Core\Security\Login;

use Core\Security\Token\AuthToken;

/**
 * Autologin.php
 *
 * @author Michael "Tekkla" Zorn <tekkla@tekkla.de>
 * @copyright 2016
 * @license MIT
 */
class Autologin extends AbstractLogin
{

    /**
     *
     * @var int
     */
    private $expires_after = 30;

    /**
     *
     * @param int $days
     */
    public function setExpiresAfter(int $days)
    {
        $this->expires_after = $days;
    }

    /**
     *
     * @return int
     */
    public function getExpiresAfter(): int
    {
        return $this->expires_after;
    }

    /**
     * Tries to autologin the user by comparing token stored in cookie with a generated token created of user
     * credentials.
     *
     * @return boolean
     */
    public function doAutoLogin()
    {
        // User already logged in?
        if ($this->session['logged_in']) {
            return true;
        }

        // No autologin when autologin already failed
        if (isset($this->session['autologin_failed'])) {

            // Remove fragments/all of autologin cookies
            setcookie($this->cookie_name, '', 1);

            // Remove the flag which forces the log off
            unset($this->session['autologin_failed']);

            return false;
        }

        // No autologin cookie no autologin ;)
        if (!isset($_COOKIE[$this->cookie_name])) {
            return false;
        }

        // Let's find the user for the token in cookie
        list ($selector, $token) = explode(':', $_COOKIE[$this->cookie_name]);

        $this->db->qb([
            'table' => 'core_auth_tokens',
            'fields' => [
                'id_auth_token',
                'id',
                'token',
                'selector',
                'expires'
            ],
            'filter' => 'selector=:selector',
            'params' => [
                ':selector' => $selector
            ]
        ]);
        $data = $this->db->all();

        foreach ($data as $auth_token) {

            // Check if token is expired?
            if (strtotime($auth_token['expires']) < time()) {
                $this->removeAutoLoginTokenAndCookie($auth_token['id']);
                continue;
            }

            // Matches the hash in db with the provided token?
            if (hash_equals($auth_token['token'], $token)) {

                // Refresh session id and delete old session
                session_regenerate_id(true);

                // Refresh autologin cookie so the user stays logged in
                // as long as he comes back before his cookie has been expired.
                $this->createAutoLoginTokenAndCookie($auth_token['id']);

                // Login user, set session flags and return true
                $this->session['logged_in'] = true;
                $this->session['user'] = $auth_token['id'];

                // Remove possible autologin failed flag
                unset($this->session['autologin_failed']);

                return $this->session['user'];
            }
        }

        // !!! Reaching this point means autologin validation failed in all ways
        // Clean up the mess and return a big bad fucking false as failed autologin result.

        // Remove token cookie
        if (isset($_COOKIE[$this->cookie_name])) {
            unset($_COOKIE[$this->cookie_name]);
        }

        // Set flag that autologin failed
        $this->session['autologin_failed'] = true;

        // Set logged in flag explicit to false
        $this->session['logged_in'] = false;

        // Set id of user explicit to 0 (guest)
        $this->session['user'] = 0;

        // sorry, no autologin
        return false;
    }

    /**
     * Set auto login cookies with user generated token
     *
     * @param int $id
     */
    public function createAutoLoginTokenAndCookie(int $id)
    {
        $authtok = new AuthToken($this->db);
        $authtok->setId($id);
        $authtok->setExpires($this->expires_after);

        setcookie($this->cookie_name, $authtok->generate(), $authtok->getExpiresTimestamp(), '/');
    }

    /**
     * Removes autologin cookies with user generated token
     *
     * @param int $id
     */
    public function removeAutoLoginTokenAndCookie(int $id)
    {
        $authtok = new AuthToken($this->db);
        $authtok->setId($id);
        $authtok->deleteUserToken();

        setcookie($this->cookie_name, '', 1, '/');
    }
}

