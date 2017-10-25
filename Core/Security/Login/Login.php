<?php
namespace Core\Security\Login;

use Core\Security\Ban\BanLogEntry;

/**
 * Login.php
 *
 * @author Michael "Tekkla" Zorn <tekkla@tekkla.de>
 * @copyright 2016
 * @license MIT
 */
class Login extends AbstractLogin
{

    /**
     *
     * @var string
     */
    private $username = '';

    /**
     *
     * @var string
     */
    private $password = '';

    /**
     *
     * @var string
     */
    private $salt = '';

    /**
     *
     * @var bool
     */
    private $remember = false;

    /**
     *
     * @var int
     */
    private $id = 0;

    /**
     *
     * @var int
     */
    private $state = 0;

    /**
     *
     * @var bool
     */
    private $ban = true;

    /**
     * Returns username
     *
     * @return string
     */
    public function getUsername(): string
    {
        return $this->username;
    }

    /**
     * Set username to perfom login with
     *
     * @param string $username
     */
    public function setUsername(string $username)
    {
        $this->username = $username;
    }

    /**
     * Returns the set password
     *
     * @return string
     */
    public function getPassword(): string
    {
        return $this->password;
    }

    /**
     * Set password to perform login with
     *
     * @param string $password
     */
    public function setPassword(string $password)
    {
        $this->password = $password;
    }

    /**
     * Returns set password salt
     *
     * @return string
     */
    public function getSalt(): string
    {
        return $this->salt;
    }

    /**
     * Sets password salt
     *
     * @param string $salt
     */
    public function setSalt(string $salt)
    {
        $this->salt = $salt;
    }

    /**
     * Return remember flag
     *
     * @return bool
     */
    public function getRemember(): bool
    {
        return $this->remember;
    }

    /**
     *
     * @param boolean $remember
     */
    public function setRemember(bool $remember)
    {
        $this->remember = $remember;
    }

    /**
     * Sets ban system active (true:default) of inactive (false)
     * @param bool $ban
     */
    public function setBan(bool $ban)
    {
        $this->ban = $ban;
    }

    /**
     * Returns state of ban system
     *
     * @return bool
     */
    public function getBan(): bool
    {
        return $this->ban;
    }

    /**
     * Returns id
     *
     * @return int
     */
    public function getId(): int
    {
        return $this->session['user'];
    }

    /**
     * Validates the provided data against user data to perform user login.
     * Offers option to activate autologin.
     *
     * @param unknown $login
     *            Login name
     * @param unknown $password
     *            Password to validate
     * @param boolean $remember_me
     *            Option to activate autologin
     *
     * @return boolean|mixed
     */
    public function doLogin()
    {
        // Empty username or password
        if (empty($this->username) || empty($this->password)) {

            if (empty($this->username)) {
                $this->username = 'none';
            }

            $this->logLogin($this->username, $this->username == 'none' ? true : false, empty($this->password));
            return false;
        }

        $this->username = trim($this->username);
        $this->password = trim($this->password);

        // Try to load user from db
        $this->db->qb([
            'table' => 'core_users',
            'fields' => [
                'id_user',
                'password',
                'state'
            ],
            'filter' => 'username=:username',
            'params' => [
                ':username' => $this->username
            ]
        ]);

        $login = $this->db->single();

        // No user found => login failed
        if (empty($login)) {

            // Log login try with not existing username
            $this->logLogin(true, false, $this->ban);
            return false;
        }

        // User needs activation?
        if ($login['state'] == 1) {
            $this->session['display_activation_by_mail'] = true;
            $this->logger->warning(sprintf('User "%s" tried to login on not activated account.', $this->username));
            return false;
        }

        if ($login['state'] == 2) {
            $this->session['display_activation_by_admin'] = true;
            $this->logger->warning(sprintf('User "%s" tried to login on account that needs to be activaed by admin.', $this->username));
            return false;
        }

        // Password ok?
        if (password_verify($this->password . $this->salt, $login['password'])) {

            // Needs hash to be updated?
            if (password_needs_rehash($login['password'], PASSWORD_DEFAULT)) {
                $this->db->qb([
                    'table' => 'core_users',
                    'method' => 'UPDATE',
                    'fields' => [
                        'password'
                    ],
                    'filter' => 'id_user = :id_user',
                    'params' => [
                        ':password' => password_hash($this->password, PASSWORD_DEFAULT),
                        ':id_user' => $login['id_user']
                    ]
                ], true);
            }

            // Refresh session id and delete old session
            session_regenerate_id(true);

            // Store essential userdata in session
            $this->session['logged_in'] = true;
            $this->session['user'] = $login['id_user'];

            // Remember for autologin?
            $autologin = new Autologin($this->db);

            if ($this->remember === true) {
                $autologin->setCookieName($this->cookie_name);
                $autologin->createAutoLoginTokenAndCookie($login['id_user']);
            }
            else {
                $autologin->removeAutoLoginTokenAndCookie($login['id_user']);
            }

            // Remove possible login_failed flag from session
            if (isset($this->session['login_failed'])) {
                unset($this->session['login_failed']);
            }

            // Log successfull login
            $this->logLogin();

            // Login is ok, return user id
            return $login['id_user'];
        }
        else {

            // Log try with wrong password and start ban counter
            $this->logLogin(false, true, $this->ban);

            return false;
        }
    }

    /**
     * Logout
     *
     * Logs out the user, removes all it's data from session, creates a new session token, removes all autologin cookies
     * and logs the logout to the log table.
     *
     * @return boolean
     */
    public function doLogout(): bool
    {
        // No user logged in
        if (empty($this->session['user'])) {
            return true;
        }

        // Store current user id for later use
        $user = $this->session['user'];

        // Remove autologin stuff?
        if ($this->remember) {
            $autologin = new Autologin($this->db);
            $autologin->setCookieName($this->cookie_name);
            $autologin->removeAutoLoginTokenAndCookie($user);
        }

        // Refresh session id and delete old session
        session_regenerate_id(true);

        // Clean up session
        unset($this->session['autologin_failed']);

        $this->session['user'] = 0;
        $this->session['logged_in'] = false;

        if (isset($this->logger)) {
            $this->logger->info('Logout: User [' . $user . ']');
        }

        return true;
    }

    /**
     * Returns login state of current user
     *
     * @return boolean
     */
    public function loggedIn()
    {
        return $this->session['logged_in'];
    }

    /**
     * Checks login state and overrides the router current data to force display of loginform.
     *
     * @return boolean
     */
    public function forceLogin(): bool
    {
        if ($this->loggedIn()) {
            return true;
        }

        /* @var $router \Core\Http\Router */
        $router = $this->di->get('core.router');
        $router->setApp('Core');
        $router->setController('Login');
        $router->setAction('Login');

        return false;
    }

    /**
     * Logs login process
     *
     * @param boolean $error_username
     *            Flag to signal that there was a problem with the username
     * @param boolean $error_password
     *            Flag to signal that there was a problem with the password
     * @param boolean $ban
     *            Flag to signal that this is a banable action
     */
    private function logLogin(bool $error_username = false, bool $error_password = false, bool $ban = true)
    {
        $text = sprintf('Login for user "%s"', $this->username);
        $state = 0;

        if ($error_username || $error_password) {

            $text .= ' failed because of wrong ';

            if ($error_username) {
                $state += 1;
                $text .= 'username';
            }

            if ($error_password) {
                $state += 2;
                $text .= 'password';
            }

            // Start ban process only when requested and only when state indicates a login error from user credentials
            if ($this->ban && $ban) {
                $banlog = new BanLogEntry($this->db);
                $banlog->setText($text);
                $banlog->setCode($state);
                $banlog->add();
            }

            if (isset($this->logger)) {
                $this->logger->warning($text, [$state]);
            }

            return;
        }

        // Still here? Log success!
        if (isset($this->logger)) {
            $this->logger->info($text . ' success');
        }
    }
}