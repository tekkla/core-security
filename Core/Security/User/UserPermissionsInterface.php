<?php
namespace Core\Security\User;

/**
 * UserPermissionsInterface.php
 *
 * @author Michael "Tekkla" Zorn <tekkla@tekkla.de>
 * @copyright 2016
 * @license MIT
 */
interface UserPermissionsInterface
{

    /**
     * Adds a permission to the permissions stack
     *
     * @param string $permission
     */
    public function add(string $permission);

    /**
     * Replaces all set permissions with the provided permissions
     *
     * @param array $permissions
     */
    public function set(array $permissions);

    /**
     * Returns all set permissions as array
     *
     * @return array
     */
    public function get(): array;

    /**
     * Checks if the user has an app related permission granted
     *
     * @param string|array $permission
     *            One permission by it's name or an array of permissionnames
     *
     * @return bool
     */
    public function allowedTo($permission): bool;
}

