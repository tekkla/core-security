<?php
namespace Core\Security\Token;

use Core\Data\Connectors\Db\Db;

/**
 * AuthToken.php
 *
 * @author Michael "Tekkla" Zorn <tekkla@tekkla.de>
 * @copyright 2016
 * @license MIT
 */
class AuthToken extends AbstractDbToken
{
    
    use RemoveExpiredTokensTrait;

    /**
     *
     * @var int
     */
    private $id;

    /**
     *
     * @var int
     */
    private $selector_size = 6;

    /**
     *
     * @var int
     */
    private $selector_size_min = 6;

    /**
     *
     * @var string
     */
    private $selector;

    /**
     *
     * @var int
     */
    private $token_size = 60;

    /**
     *
     * @var int
     */
    private $token_size_min = 12;

    /**
     *
     * @var int
     */
    private $expires_days = 30;

    /**
     *
     * @var string
     */
    private $expires_datetime;

    /**
     *
     * @var int
     */
    private $expires_timestamp;

    /**
     * Constructor
     *
     * @param Db $db
     *            Necessary Db object to store auth token in database
     */
    public function __construct(Db $db)
    {
        parent::__construct($db);
        
        $this->setExpires($this->expires_days);
    }

    /**
     * Sets id under which the token gets stored.
     *
     * Ideally this is the id of the user the token belongs to.
     *
     * @param int $id
     */
    public function setId(int $id)
    {
        $this->id = $id;
    }

    /**
     * Returns set id
     *
     * @return int
     */
    public function getId(): int
    {
        return $this->id;
    }

    /**
     * Sets a selector which gets used instead of generate one
     *
     * @param string $selector
     *
     * @throws TokenException
     */
    public function setSelector(string $selector)
    {
        if (empty($selector)) {
            Throw new TokenException('Empty selectors are not allowed.');
        }
        
        $this->selector = $selector;
    }

    /**
     * Returns set selector
     *
     * Generates a selector when not set.
     *
     * @return string
     */
    public function getSelector(): string
    {
        if (empty($this->selector)) {
            $this->setSize($this->selector_size);
            $this->selector = $this->generateRandomToken();
        }
        
        return $this->selector;
    }

    /**
     * Sets a token which gets used instead of generate one
     *
     * @param string $token
     *
     * @throws TokenException
     */
    public function setToken(string $token)
    {
        if (empty($selector)) {
            Throw new TokenException('Empty tokens are not allowed.');
        }
        
        $this->token = $token;
    }

    /**
     * Returns set token.
     *
     * Generates a token when not set.
     *
     * @return string
     */
    public function getToken(): string
    {
        if (empty($this->token)) {
            $this->setSize($this->token_size);
            $this->token = $this->generateRandomToken();
        }
        
        return $this->token;
    }

    /**
     * Sets selector size
     *
     * @param int $selector_size
     *
     * @throws TokenException when $selector_size is lower than 8.
     */
    public function setSelectorSize(int $selector_size)
    {
        if ($selector_size < $this->selector_size_min) {
            Throw new TokenException(sprintf('Minimum size of selector in AuthToken is %d', $this->selector_size_min));
        }
        
        $this->selector_size = $selector_size;
    }

    /**
     * Returns size of selector
     *
     * @return int
     */
    public function getSelectorSize(): int
    {
        return $this->selector_size;
    }

    /**
     * Sets size of token
     *
     * @param int $token_size
     *
     * @throws TokenException when $tokens_size is lower than 16.
     */
    public function setTokenSize(int $token_size)
    {
        if ($token_size < $this->token_size_min) {
            Throw new TokenException(sprintf('Minimum size of token in AuthToken is %d', $this->token_size_min));
        }
        
        $this->token_size = $token_size;
    }

    /**
     * Returns size of token
     *
     * @return int
     */
    public function getTokenSize(): int
    {
        return $this->token_size;
    }

    /**
     * Sets days after token gets expired
     *
     * @param int $days
     */
    public function setExpires(int $days)
    {
        $this->expires_days = $days;
        
        $time = strtotime('+ ' . $this->expires_days . ' days');
        
        $this->expires_datetime = date('Y-m-d H:i:s', $time);
        $this->expires_timestamp = $time;
    }

    /**
     * Returns the days after token gets expired
     *
     * @return int
     */
    public function getExpires(): int
    {
        return $this->expires;
    }

    /**
     * Returns a timestamp based on set day until expires
     *
     * @return int
     */
    public function getExpiresTimestamp(): int
    {
        return $this->expires_timestamp;
    }

    /**
     * Returns a date/time value when the token gets expired
     *
     * @return STRING
     */
    public function getExpiresDateTime(): string
    {
        return $this->expires_datetime;
    }

    /**
     * Generates the auth token parts, stores them database and returns them
     *
     * @throws TokenException
     *
     * @return array
     */
    public function generate(): string
    {
        $this->removeExpiredTokens();
        
        if (empty($this->id)) {
            Throw new TokenException('Cannot create AuthToken for empty id.');
        }
        
        // Create selector
        $selector = bin2hex($this->getSelector());
        
        // Create token
        $token = hash('sha256', $this->getToken());
        
        // Store selector and tokenb in DB
        $this->db->qb([
            'table' => 'core_auth_tokens',
            'method' => 'INSERT',
            'primary' => 'id_auth_token',
            'data' => [
                'selector' => $selector,
                'token' => $token,
                'id' => $this->id,
                'expires' => $this->expires_datetime
            ]
        ], true);
        
        // Set autologin token cookie only when token is stored successfully in db!!!
        if (empty($this->db->lastInsertId())) {
            
            $msg = 'AuthToken could not be stored in database.';
            
            if (isset($this->logger)) {
                $this->logger->warning($msg, __METHOD__);
            }
            
            Throw new TokenException($msg);
        }
        
        return $selector . ':' . $token;
    }

    /**
     * Removes the token of a user from auth_token table and all tokens expired.
     *
     * @param int $id_user
     */
    public function deleteUserToken()
    {
        $this->removeExpiredTokens();
        
        if (empty($this->id)) {
            
            $msg = '%s: Can not delete auth tokens without a corresponding id. Use AuthToken::setId() to set an id before calling this method. Deletion of auth token aborted!';
            
            if (isset($this->logger)) {
                $this->logger->warning($msg, __METHOD__);
                return;
            } else {
                Throw new TokenException($msg);
            }
        }
        
        // Yep! Delete token and return false for failed autologin
        $this->db->qb([
            'table' => 'core_auth_tokens',
            'method' => 'DELETE',
            'filter' => 'expires < :expires OR id=:id',
            'params' => [
                ':expires' => date('Y-m-d H:i:s'),
                ':id' => $this->id
            ]
        ], true);
    }
}
