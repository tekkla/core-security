<?php
namespace Core\Security\User;

/**
 * UserGroups.php
 *
 * @author Michael "Tekkla" Zorn <tekkla@tekkla.de>
 * @copyright 2016
 * @license MIT
 */
class UserGroups
{

    /**
     *
     * @var array
     */
    private $groups = [];

    /**
     * Adds a group to the groups stack
     *
     * @param string $group
     */
    public function add(string $group)
    {
        $this->groups[] = $group;
    }

    /**
     * Replaces all set groups with the provided groups
     *
     * @param array $groups
     */
    public function set(array $groups)
    {
        $this->groups = $groups;
    }

    /**
     * Checks
     *
     * @param string $group
     *
     * @return bool
     */
    public function in(string $group)
    {
        return in_array($group, $this->groups);
    }

    /**
     *
     * @param string $group
     *
     * @return boolean
     */
    public function __isset(string $group)
    {
        return $this->in($group);
    }
}

