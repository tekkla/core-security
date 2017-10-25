<?php
namespace Core\Security\Token;

/**
 * SessionToken.php
 *
 * @author Michael "Tekkla" Zorn <tekkla@tekkla.de>
 * @copyright 2016
 * @license MIT
 */
class SessionToken extends AbstractToken
{

    /**
     * Reference to session
     *
     * @var array
     */
    private $session;

    /**
     * Name of the token
     *
     * @var string
     */
    private $name = 'token';

    /**
     * Constructor
     *
     * Creates a reference to $_SESSION['Core']['Security'] and binds it to $session property.
     *
     * @param string $token_name
     *            Optional name for the token. Default name is 'session.token'
     */
    public function __construct(string $token_name = null)
    {
        if (empty($_SESSION['Core']['Security'])) {
            $_SESSION['Core']['Security'] = [];
        }

        $this->session = &$_SESSION['Core']['Security'];

        if (isset($token_name)) {
            $this->name = $token_name;
        }

        // Do we have an token set in session that we can should use as token?
        if (!empty($this->session[$this->name])) {
            $this->token = $this->session[$this->name];
        }
    }

    /**
     * Sets name of token
     *
     * @var string $name
     */
    public function setTokenName(string $name)
    {
        if (empty($name)) {
            Throw new TokenException('Empty token name is not allowed.');
        }

        $this->name = $name;
    }

    /**
     * Sets session reference
     *
     * @param array $session
     */
    public function setSessionReference(array &$session)
    {
        $this->session = $session;
    }

    /**
     *
     * @return bool
     */
    public function exists(): bool
    {
        return isset($this->token);
    }

    /**
     * Generates a token, stores it in the set session reference and returns the token
     *
     * The token gets stored in $_SESSION['Core']['Security']['session.token'] by default.
     *
     * @return string
     */
    public function generate(): string
    {
        $this->token = hash('sha256', $this->generateRandomToken());
        $this->session[$this->name] = $this->token;

        return $this->token;
    }

    public function getToken(): string
    {
        if (!isset($this->token)) {
            $this->generate();
        }

        return $this->token;
    }

    /**
     * Validates $token against the random token stored in session
     *
     * @param string $token
     *
     * @return bool
     */
    public function validateRandomSessionToken(string $token): bool
    {
        if (!isset($this->session[$this->name])) {
            return false;
        }

        return $token == $this->session[$this->name];
    }
}

