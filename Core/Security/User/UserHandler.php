<?php
namespace Core\Security\User;

use Core\Data\Connectors\Db\Db;
use Core\Security\Password\HashGenerator;
use Core\Security\AbstractSecurity;
use Core\Security\Token\ActivationToken;
use Core\Toolbox\Strings\CamelCase;

/**
 * UserHandler.php
 *
 * @author Michael "Tekkla" Zorn <tekkla@tekkla.de>
 * @copyright 2016-2018
 * @license MIT
 */
class UserHandler extends AbstractSecurity
{

    /**
     *
     * @var Db
     */
    private $db;

    /**
     *
     * @var string
     */
    private $table = 'core_users';

    /**
     *
     * @var string
     */
    private $salt;

    /**
     * Constructor
     *
     * @param Db $db
     *            Db dependency
     */
    public function __construct(Db $db)
    {
        $this->db = $db;
    }

    /**
     * Sets salt to be used on password changes
     *
     * @param string $salt
     */
    public function setSalt(string $salt)
    {
        $this->salt = $salt;
    }

    /**
     * Creates a new user
     *
     * Important: The passwort set in User object will be transformed into a hash value. After that the password of the
     * User object gets replaced with this hash.
     *
     * @param User $user
     *            User object to create user for
     * @param boolean $state
     *            Set to true if user should be autoactivated
     *            
     * @throws UserException
     *
     * @return integer
     */
    public function createUser(User $user): int
    {
        $username = $user->getUsername();
        
        if ($username == 'guest') {
            Throw new UserException('Cannot create user without username.');
        }
        
        if (empty($user->getPassword())) {
            Throw new UserException('Cannot create user without a password');
        }
        
        // Check for already existing username
        $exists = $this->db->count($this->table, 'username=:username', [
            ':username' => $username
        ]);
        
        if ($exists > 0) {
            Throw new UserException(sprintf('The username "%s" is already in use.', $username));
        }
        
        try {
            
            $this->db->beginTransaction();
            $this->db->qb([
                'table' => $this->table,
                'data' => [
                    'username' => $username,
                    'display_name' => $user->getDisplayname(),
                    'state' => $user->getState()
                ]
            ], true);
            
            // Get our new user id
            $id = $this->db->lastInsertId();
            
            if (! empty($id)) {
                
                // Set new id to users object
                $user->setId($id);
                
                // Create password hash
                $this->changePassword($user);
                
                $this->db->endTransaction();
            }
        } catch (\Throwable $t) {
            Throw new UserException($t->getMessage(), $t->getCode());
        }
        
        return $id;
    }

    /**
     * Loads user from DB.
     *
     * Takes care about not to load a user more than once
     *
     * @param User $user
     */
    public function loadUser(User $user)
    {
        // Guests do not have a user id. So do not try to load data for guests.
        if ($user->permissions->isGuest()) {
            return;
        }
        
        $this->db->qb([
            'table' => $this->table,
            'field' => [
                'username',
                'display_name',
                'state'
            ],
            'filter' => 'id_user=:id_user',
            'params' => [
                ':id_user' => $user->getId()
            ]
        ]);
        
        $data = $this->db->single();
        
        if (! empty($data)) {
            
            $user->setUsername($data['username']);
            
            // Use username as display_name when there is no display_name for this user
            $user->setDisplayName(empty($data['display_name']) ? $data['username'] : $data['display_name']);
            
            // Load the groups the user is in
            $this->db->qb([
                'table' => 'core_users_groups',
                'fields' => 'id_group',
                'filter' => 'id_user=:id_user',
                'params' => [
                    ':id_user' => $user->getId()
                ]
            ]);
            
            $groups = $this->db->column();
            
            if (! empty($groups)) {
                
                $user->groups->set($groups);
                
                // Create a prepared string and param array to use in query
                $prepared = $this->db->prepareArrayQuery('group', $groups);
                
                // Get and return the permissions
                $this->db->qb([
                    'table' => 'core_groups_permissions',
                    'fields' => [
                        'storage',
                        'permission'
                    ],
                    'method' => 'SELECT DISTINCT',
                    'filter' => 'id_group IN (' . $prepared['sql'] . ')',
                    'params' => $prepared['values']
                ]);
                
                $permissions = $this->db->all();
                
                $temp_perms = [];
                
                $string = new CamelCase('');
                
                foreach ($permissions as $perm) {
                    $string->setString($perm['storage']);
                    $user->permissions->add($string->uncamelize() . '.' . $perm['permission']);
                }
                
                // Is the user an admin?
                if (! empty($user->permissions->allowedTo('core.admin'))) {
                    $user->permissions->setAdmin(true);
                }
            }
        }
    }

    /**
     * Changes password of a user
     *
     * Important: The passwort set in User object will be transformed into a hash value. After that the password of the
     * User object gets replaced with this hash.
     *
     * @param User $user
     *
     * @throws UserException
     */
    public function changePassword(User $user)
    {
        if ($user->permissions->isGuest()) {
            Throw new UserException('Cannot change password of a guest.');
        }
        
        if (empty($user->getPassword())) {
            Throw new UserException('Cannot change an empty password');
        }
        
        $hashgen = new HashGenerator($user->getPassword());
        $hashgen->setSalt($this->salt);
        $password = $hashgen->generate();
        
        // Check the old password
        $this->db->qb([
            'table' => $this->table,
            'method' => 'UPDATE',
            'fields' => 'password',
            'filter' => 'id_user=:id_user',
            'params' => [
                ':id_user' => $user->getId(),
                ':password' => $password
            ]
        ], true);
        
        $user->setPassword($password);
    }

    /**
     * Updates a user with data from User object
     *
     * @param User $user
     * @param bool $refresh_password
     *            Optional flag to force a refresh aka rehash of the given password
     *            
     * @throws UserException
     */
    public function updateUser(User $user, bool $refresh_password = false)
    {
        if ($user->permissions->isGuest()) {
            Throw new UserException('Cannot change password of a guest.');
        }
        
        // Check the old password
        $this->db->qb([
            'table' => $this->table,
            'primary' => 'id_user',
            'data' => [
                'username' => $user->getUsername(),
                'display_name' => $user->getDisplayname(),
                'state' => $user->getState(),
                'id_user' => $user->getId()
            ]
        ], true);
        
        if ($refresh_password) {
            $this->changePassword($user);
        }
    }

    /**
     * Deletes a user
     *
     * @param User $user
     */
    public function deleteUser(User $user)
    {
        if ($user->permission->isGuest()) {
            Throw new UserException('Cannot delete a guest user.');
        }
        
        // Check the old password
        $this->db->delete($this->table, 'id_user=:id_user', [
            ':id_user' => $user->getId()
        ]);
    }

    /**
     * Denies an activation of user with selector:token key
     *
     * @param string $key
     *
     * @return bool
     */
    public function denyActivation(string $key): bool
    {
        
        // Get tokendate from db
        $tokenhandler = new ActivationToken($this->db);
        $tokenhandler->setSelectorTokenString($key);
        $tokenhandler->loadTokenData();
        
        // Get tokendate from db
        $id_user = $tokenhandler->getUserId();
        
        // Nothings to do when already removed
        if (empty($id_user)) {
            return false;
        }
        
        // Remove the user and the token
        $this->deleteUser(new User($id_user));
        $tokenhandler->deleteActivationToken();
        
        return true;
    }

    /**
     * Actives user by using a selector:token key
     *
     * @param string $key
     *            Key to use for activation
     */
    public function activateUser(string $key)
    {
        
        // Get tokendate from db
        $tokenhandler = new ActivationToken($this->db);
        $tokenhandler->setSelectorTokenString($key);
        
        // Store the current to extracted from selector:token string ($key)
        $token_from_key = $tokenhandler->getActivationToken();
        
        // Load the tokendata by using the selector from selector:token string ($key)
        $tokenhandler->loadTokenData();
        
        // Get user id
        $id_user = $tokenhandler->getUserId();
        
        // No user id means the activation must fail
        if (empty($id_user)) {
            return false;
        }
        
        // Get the token loaded from db via selector from selector:token string ($key)
        $token_from_db = $tokenhandler->getActivationToken();
        
        // Matching hashes?
        if (! hash_equals($token_from_key, $token_from_db)) {
            return false;
        }
        
        // Activate user
        $this->db->qb([
            'table' => $this->table,
            'method' => 'UPDATE',
            'fields' => 'state',
            'filter' => 'id_user=:id_user',
            'params' => [
                ':state' => 0,
                ':id_user' => $id_user
            ]
        ], true);
        
        // and delete the token of this user
        $tokenhandler->deleteActivationToken();
        
        // And finally return user id
        return $id_user;
    }
}
