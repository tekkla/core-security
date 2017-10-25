<?php
namespace Core\Security\Group;

use Core\Data\Connectors\Db\Db;

/**
 * Group.php
 *
 * @author Michael "Tekkla" Zorn <tekkla@tekkla.de>
 * @copyright 2016
 * @license MIT
 */
class Group
{

    /**
     * Default groups that cannot be overridden
     *
     * @var array
     */
    private $default_groups = [
        - 1 => 'guest',
        1 => 'admin',
        2 => 'user'
    ];

    /**
     * Groups array we work with
     *
     * @var array
     */
    private $groups = [
        'Core' => []
    ];

    /**
     *
     * @var array
     */
    private $byid = [];

    /**
     * Used group ids and title
     *
     * @var array
     */
    private $used = [];

    /**
     * DB Connector
     *
     * @var Db
     */
    private $db;

    /**
     */
    function __construct(Db $db)
    {
        $this->db = $db;

        $this->loadGroups();
    }

    public function loadGroups()
    {
        // Copy default groups to
        // $this->groups = $this->default_groups;
        $this->db->qb([
            'table' => 'core_groups',
            'fields' => [
                'storage',
                'id_group',
                'title',
                'display_name',
                'description'
            ],
            'order' => 'id_group'
        ]);
        $this->db->execute();

        $groups = $this->db->fetchAll();

        foreach ($groups as $g) {
            $this->addGroup($g['app'], $g['id_group'], $g['title'], $g['display_name'], $g['description']);
        }
    }

    /**
     *
     * @throws DatabaseException
     */
    public function saveGroups()
    {
        // Get usergroups without the default ones
        $groups = array_intersect_key($this->default_groups, $this->groups);

        try {

            // Important: Use a transaction!
            $this->db->beginTransaction();

            // Delete current groups
            $this->db->qb([
                'table' => 'core_groups',
                'method' => 'DELETE'
            ]);
            $this->db->execute();

            // Prepare statement for group insert
            $this->db->qb([
                'table' => 'core_groups',
                'method' => 'INSERT',
                'fields' => [
                    'id_group',
                    'title'
                ]
            ]);

            // Insert the groups each by each into the groups table
            foreach ($groups as $id_group => $title) {
                $this->db->bindValue(':id_group', $id_group);
                $this->db->bindValue(':title', $title);
                $this->db->execute();
            }

            // End end or transaction
            $this->db->endTransaction();
        }
        catch (\PDOException $e) {
            $this->db->cancelTransaction();
            Throw new GroupException($e->getMessage(), $e->getCode(), $e->getPrevious());
        }
    }

    /**
     *
     * @param integer $id_group
     * @param string $title
     *
     * @throws GroupException
     */
    public function addGroup($app, $id_group, $title, $display_name, $description = '')
    {
        // Check for group id already in use
        if (array_key_exists($id_group, $this->used)) {
            Throw new GroupException(sprintf('A usergroup with id "%s" already exists.', $id_group));
        }

        // Check for group name already in use
        if (in_array($app . '.' . $title, $this->used)) {
            Throw new GroupException(sprintf('A usergroup with title "%s" already exists for app "%s".', $title, $app));
        }

        $group = [
            'app' => $app,
            'id_group' => $id_group,
            'title' => $title,
            'display_name' => $display_name,
            'description' => $description
        ];

        $this->groups[$app][$id_group] = $group;
        $this->byid[$id_group] = $group;
        $this->used[$id_group] = $app . '.' . $title;
    }

    /**
     * Removes a group from DB and groups list
     *
     * @param integer $id_group
     *
     *
     * @throws DatabaseException
     */
    public function removeGroup($id_group)
    {
        try {

            $this->db->beginTransaction();

            // Delete usergroup
            $this->db->qb([
                'table' => 'core_groups',
                'method' => 'DELETE',
                'filter' => 'id_group = :id_group',
                'params' => [
                    ':id_group' => $id_group
                ]
            ]);
            $this->db->execute();

            // Delete permissions related to this group
            $this->db->qb([
                'table' => 'core_permissions',
                'method' => 'DELETE',
                'filter' => 'id_group = :id_group',
                'params' => [
                    ':id_group' => $id_group
                ]
            ]);
            $this->db->execute();

            // Remove group from current grouplist
            unset($this->groups[$id_group]);

            $this->db->endTransaction();
        }
        catch (\PDOException $e) {

            $this->db->cancelTransaction();

            Throw new GroupException($e->getMessage(), $e->getCode(), $e->getPrevious());
        }
    }

    /**
     * Returns all groups
     *
     * @return array
     */
    public function getGroups($byid = false, $skip_guest = false)
    {
        if ($byid) {

            $data = $this->byid;

            if ($skip_guest) {
                unset($data[- 1]);
            }
        }
        else {
            $data = $this->groups;

            if ($skip_guest) {
                unset($data['Core'][- 1]);
            }
        }

        return $data;
    }

    /**
     * Returns a group by it's id
     *
     * @param int $id_group
     *            Internal id of group
     *
     * @return mixed|boolean
     */
    public function getGroupById($id_group)
    {
        if (array_key_exists($id_group, $this->byid)) {
            return $this->byid[$id_group];
        }

        return false;
    }

    /**
     * Returns a group by app and name
     *
     * @param string $app
     *            Name of related app
     * @param string $name
     *            Name of group
     *
     * @return mixed|boolean
     */
    public function getGroupByAppAndName($app, $name)
    {
        if (array_key_exists($app, $this->groups) && array_key_exists($name, $this->groups[$app])) {
            return $this->groups[$app][$name];
        }

        return false;
    }
}
