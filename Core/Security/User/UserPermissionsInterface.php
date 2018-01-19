<?php
namespace Core\Security\User;

/**
 * UserPermissionsInterface.php
 *
 * @author Michael "Tekkla" Zorn <tekkla@tekkla.de>
 * @copyright 2016-2018
 * @license MIT
 */
interface UserPermissionsInterface
{

    /*
     * Checks the user for to be a guest. 
     * 
     * Is true by default until the user logs in.
     *
     * @return bool
     */
    public function isGuest(): bool;

    /**
     * Flags this user as guest
     *
     * @param bool $guest
     */
    public function setGuest(bool $guest);
    
    /**
     * Returns admin flag of the user
     *
     * @return bool
     */
    public function getGuest(): bool;
    
    /**
     * Flags this user as global admin
     *
     * @param bool $admin
     */
    public function setAdmin(bool $admin);
    
    /**
     * Returns admin flag of the user
     *
     * @return bool
     */
    public function getAdmin(): bool;
    
    /**
     * Synonym for getAdmin() method
     *
     * @return boolean
     */
    public function isAdmin(): bool;
    
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

