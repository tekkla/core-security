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
     * @var array
     */
    protected $permissions = [];

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

        if (empty($this->permissions)) {
            return true;
        }

        if (!is_array($permission)) {
            $permission = (array) $permission;
        }

        foreach ($permission as $perm) {
            if (in_array($perm, $this->permissions)) {
                return true;
            }
        }

        return false;
    }
}

