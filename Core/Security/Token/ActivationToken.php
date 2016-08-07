<?php
namespace Core\Security\Token;

use Core\Data\Connectors\Db\Db;

/**
 * ActivationToken.php
 *
 * @author Michael "Tekkla" Zorn <tekkla@tekkla.de>
 * @copyright 2016
 * @license MIT
 */
class ActivationToken extends AbstractDbToken
{

    use RemoveExpiredTokensTrait;
    use MissingUserIdTrait;

    /**
     *
     * @var string
     */
    private $table = 'core_activation_tokens';

    /**
     *
     * @var int
     */
    protected $id_user = 0;

    /**
     *
     * @var int
     */
    protected $ttl = 864000;

    /**
     *
     * @var int
     */
    protected $expires = 0;

    /**
     *
     * @var string
     */
    protected $selector;

    /**
     *
     * @var string
     */
    protected $activation_token;

    /**
     *
     * @var string
     */
    protected $string;

    /**
     * Constructor
     *
     * @param Db $db
     */
    public function __construct(Db $db)
    {
        $this->expires = time() + $this->ttl;

        parent::__construct($db);
    }

    /**
     * Set a selector:token string
     *
     * @param string $key
     */
    public function setSelectorTokenString(string $string)
    {
        if (strpos($string, ':') === false) {
            Throw new TokenException('AuthToken: The key is no valid selector:token string.');
        }
        $this->string = urldecode($string);

        $parts = explode(':', $this->string);

        $this->selector = $parts[0];
        $this->activation_token = $parts[1];
    }

    /**
     * Set user id
     *
     * @param int $id
     */
    public function setUserId(int $id)
    {
        $this->id_user = $id;
    }

    /**
     * Returns user id
     *
     * @return int
     */
    public function getUserId(): int
    {
        return $this->id_user;
    }

    /**
     * Creates a random and unique selector
     *
     * @return string
     */
    private function generateSelector(): string
    {
        // Make sure the selector is not in use. Such case is very uncommon and rare but can happen.
        $in_use = true;

        while ($in_use == true) {

            // Generate random selector and token
            $this->setSize(6);
            $this->generateRandomToken();

            $selector = bin2hex($this->token);

            // And check if it is already in use
            $in_use = $this->db->count('core_activation_tokens', 'selector = :selector', [
                'selector' => $selector
            ]) > 0;
        }

        $this->selector = $selector;

        return $this->selector;
    }

    /**
     * Returns the selector.
     *
     * Will generate a random and unique selector when no selector is set.
     *
     * @return string
     */
    public function getSelector(bool $refresh = false): string
    {
        if (!isset($this->selector) || $refresh) {
            $this->generateSelector();
        }

        return $this->selector;
    }

    /**
     * Generates a random sha265 token
     */
    private function generateActivationToken(): string
    {
        $this->setSize(32);
        $this->generateRandomToken();

        $this->activation_token = hash('sha256', $this->token);

        return $this->activation_token;
    }

    public function getActivationToken(bool $refresh = false): string
    {
        if (!isset($this->activation_token) || $refresh) {
            $this->generateActivationToken();
        }

        return $this->activation_token;
    }

    /**
     * Returns the expires timestamp from now + set ttl
     *
     * @return int
     */
    public function getExpires(): int
    {
        return time() + $this->ttl;
    }

    /**
     * Creates an activation token for a user in db and returns selector:token string
     *
     * @return string
     */
    public function createActivationToken()
    {
        // No token without user id!
        if ($this->checkMissingUserId() === true) {
            return;
        }

        // First: clean all expired tokens!
        $this->removeExpiredTokens();

        // Delete all existing tokens of this user
        $this->db->delete($this->table, 'id_user=:id_user', [
            'id_user' => $this->id_user
        ]);

        $data = [
            'id_user' => $this->id_user,
            'selector' => $this->getSelector(),
            'token' => $this->getActivationToken(),
            'expires' => $this->getExpires()
        ];

        $this->db->qb([
            'table' => $this->table,
            'data' => $data
        ], true);

        return $this->selector . ':' . $this->activation_token;
    }

    public function loadTokenData()
    {
        if (!isset($this->string)) {
            Throw new TokenException('No selector:token string set.');
        }

        // First: clean all expired tokens!
        $this->removeExpiredTokens();

        $this->db->qb([
            'table' => $this->table,
            'fields' => [
                'id_user',
                'token'
            ],
            'filter' => 'selector=:selector',
            'params' => [
                ':selector' => $this->selector
            ]
        ]);

        $result = $this->db->single();

        if (!$result) {
            return false;
        }

        $this->activation_token = $result['token'];
        $this->id_user = $result['id_user'];
    }

    public function deleteActivationToken()
    {
        if ($this->checkMissingUserId() === true) {
            return;
        }

        $this->db->delete($this->table, 'id_user=:id_user', [
            'id_user' => $this->id_user
        ]);
    }

    public function getActivationDataOfUser()
    {
        if ($this->checkMissingUserId() === true) {
            return;
        }

        // First: clean all expired tokens!
        $this->removeExpiredTokens();

        return $this->db->find($this->table, 'id_user', $this->id_user);
    }

    public function removeExpiredTokens()
    {
        $token_tables = [
            $this->table
        ];

        foreach ($token_tables as $table) {
            $this->db->delete($table, 'expires < :time', [
                'time' => time()
            ]);
        }
    }
}
