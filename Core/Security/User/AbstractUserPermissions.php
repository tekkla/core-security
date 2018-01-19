<?php
namespace Core\Security\User;

/**
 * AbstractUserPermissions.php
 *
 * @author Michael "Tekkla" Zorn <tekkla@tekkla.de>
 * @copyright 2016
 * @license MIT
 */
abstract class AbstractUserPermissions implements UserPermissionsInterface
{

    /**
     *
     * @var bool
     */
    protected $guest = true;

    /**
     *
     * @var bool
     */
    protected $admin = false;

    /**
     *
     * @var array
     */
    protected $permissions = [];

    /**
     *
     * {@inheritdoc}
     * @see \Core\Security\User\UserPermissionsInterface::getAdmin()
     */
    public function getAdmin(): bool
    {
        return $this->admin;
    }

    /**
     *
     * {@inheritdoc}
     * @see \Core\Security\User\UserPermissionsInterface::getGuest()
     */
    public function getGuest(): bool
    {
        return $this->guest;
    }

    /**
     *
     * {@inheritdoc}
     * @see \Core\Security\User\UserPermissionsInterface::isAdmin()
     */
    public function isAdmin(): bool
    {
        return $this->admin;
    }

    /**
     *
     * {@inheritdoc}
     * @see \Core\Security\User\UserPermissionsInterface::isGuest()
     */
    public function isGuest(): bool
    {
        return $this->guest;
    }

    /**
     *
     * {@inheritdoc}
     * @see \Core\Security\User\UserPermissionsInterface::setAdmin()
     */
    public function setAdmin(bool $admin)
    {
        $this->admin = $admin;
    }

    /**
     *
     * {@inheritdoc}
     * @see \Core\Security\User\UserPermissionsInterface::setGuest()
     */
    public function setGuest(bool $guest)
    {
        $this->guest = $guest;
    }

    /**
     *
     * {@inheritdoc}
     *
     * @see \Core\Security\User\UserPermissionsInterface::add($permission)
     */
    public function add(string $permission)
    {
        $this->permissions[] = $permission;
    }

    /**
     *
     * {@inheritdoc}
     *
     * @see \Core\Security\User\UserPermissionsInterface::set($permissions)
     */
    public function set(array $permissions)
    {
        $this->permissions = $permissions;
    }

    /**
     *
     * {@inheritdoc}
     *
     * @see \Core\Security\User\UserPermissionsInterface::get()
     */
    public function get(): array
    {
        return $this->permissions;
    }

    /**
     *
     * {@inheritdoc}
     *
     * @see \Core\Security\User\UserPermissionsInterface::allowedTo($permission)
     */
    public function allowedTo($permission): bool
    {
        if ($this->isGuest()) {
            return false;
        }
        
        if ($this->isAdmin()) {
            return true;
        }
        
        if (empty($this->permissions)) {
            return true;
        }
        
        if (! is_array($permission)) {
            $permission = (array) $permission;
        }
        
        if (count(array_intersect($permission, $this->permissions)) > 0) {
            return true;
        }
        
        return false;
    }
}
