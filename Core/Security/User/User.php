<?php
namespace Core\Security\User;

/**
 * User.php
 *
 * @author Michael "Tekkla" Zorn <tekkla@tekkla.de>
 * @copyright 2016
 * @license MIT
 */
class User
{

    /**
     *
     * @var int
     */
    private $id = 0;

    /**
     *
     * @var string
     */
    private $username;

    /**
     *
     * @var string
     */
    private $display_name;

    /**
     *
     * @var int
     */
    private $state = 2;

    /**
     *
     * @var bool
     */
    private $admin = false;

    /**
     *
     * @var string
     */
    private $password = '';

    /**
     * Access on users groups
     *
     * @var UserGroups
     */
    public $groups;

    /**
     * Permissions grouped by app
     *
     * @var array
     */
    public $permissions = [];

    /**
     * Constructor
     *
     * @param int $id
     */
    public function __construct(int $id = 0)
    {
        if (!empty($id)) {
            $this->id = $id;
        }

        $this->groups = new UserGroups();
    }

    /*
     * Checks the user for to be a guest. Is true when user is not logged in.
     *
     * @return boolean
     */
    public function isGuest(): bool
    {
        return empty($this->id);
    }

    /**
     * Flags this user as global admin
     *
     * @param bool $admin
     */
    public function setAdmin(bool $admin)
    {
        $this->admin = $admin;
    }

    public function getAdmin(): bool
    {
        return $this->admin;
    }

    /**
     * Sets the user id
     *
     * @param int $id
     */
    public function setId(int $id)
    {
        $this->id = $id;
    }

    /**
     * Returns user id
     *
     * Returns 0 when user ist not logged in which means this user is a guest.
     *
     * @return int
     */
    public function getId(): int
    {
        return $this->id;
    }

    public function setUsername(string $username)
    {
        if (empty($username)) {
            Throw new UserException('An empty username is not allowed.');
        }

        $this->username = $username;
    }

    /**
     * Returns the users login name
     *
     * @return string
     */
    public function getUsername(): string
    {
        return $this->username ?? 'guest';
    }

    /**
     * Sets users display name
     *
     * @param string $display_name
     */
    public function setDisplayName(string $display_name)
    {
        $this->display_name = $display_name;
    }

    /**
     * Returns the users displayname
     *
     * When there is no display name the method will look for a username and return this if set.
     * Otherwise the return value will be 'guest'.
     *
     * @return string
     */
    public function getDisplayname(): string
    {
        if (!isset($this->display_name)) {
            return $this->username ?? 'guest';
        }

        return $this->display_name;
    }

    /**
     * Sets a password
     *
     * @param string $password
     */
    public function setPassword(string $password)
    {
        $this->password = $password;
    }

    /**
     * Returns set password
     *
     * Remember that the password in db is only a hash value. So this getter will returnd plain password only when it is
     * set in before over setPassword()
     *
     * @return string
     */
    public function getPassword(): string
    {
        return $this->password;
    }

    /**
     * Sets user activation state
     *
     * 0 = User is activated
     * 1 = Awaits activation by mail
     * 2 = Awaits activation by admin
     *
     * @param int $state
     */
    public function setState(int $state)
    {
        if ($state < 0 || $state > 2) {
            Throw new UserException('Users state value can be 0 (active), 1 (awaits activation by mail) or 2 (awaits activation by admin)');
        }

        $this->state = $state;
    }

    /**
     * Returns users activation state
     *
     * 0 = User is activated
     * 1 = Awaits activation by mail
     * 2 = Awaits activation by admin
     *
     * @return int
     */
    public function getState(): int
    {
        return $this->state;
    }

    /**
     * Checks user access by permissions
     *
     * @param array $permissions
     * @param bool $force
     *
     * @return bool
     */
    public function checkAccess(array $permissions = [], bool $force = false): bool
    {
        // Guests are not allowed by default
        if ($this->isGuest()) {
            return false;
        }

        // Allow access to all users when permissions argument is empty
        if (empty($permissions)) {
            return true;
        }

        // Administrators are supermen :P
        if ($this->isAdmin()) {
            return true;
        }

        // User has the right to do this?
        if (count(array_intersect($permissions, $this->perissions)) > 0) {
            return true;
        }

        // You aren't allowed, by default.
        return false;
    }
}
