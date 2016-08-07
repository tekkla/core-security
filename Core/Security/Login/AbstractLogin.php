<?php
namespace Core\Security\Login;

use Core\Data\Connectors\Db\Db;
use Core\Security\AbstractSecurity;

/**
 * AbstractLogin.php
 *
 * @author Michael "Tekkla" Zorn <tekkla@tekkla.de>
 * @copyright 2016
 * @license MIT
 */
abstract class AbstractLogin extends AbstractSecurity
{

    /**
     *
     * @var array
     */
    protected $session;

    /**
     *
     * @var string
     */
    protected $cookie_name = 'CoreSecurityToken';

    /**
     *
     * @var Db
     */
    protected $db;

    /**
     * Constructor
     *
     * Creates a reference to $_SESSION['Core']['Security'] and binds it to $session property.
     */
    public function __construct(Db $db)
    {
        if (empty($_SESSION['Core']['Security'])) {
            $_SESSION['Core']['Security'] = [
                'logged_in' => false,
                'user' => 0,
            ];
        }

        $this->session = &$_SESSION['Core']['Security'];
        $this->db = $db;
    }

    /**
     * *
     * Sets login token cookie name
     *
     * @param string $cookie_name
     *            Name of the token cookie
     *
     * @throws LoginException
     */
    public function setCookieName(string $cookie_name)
    {
        if (empty($cookie_name)) {
            Throw new LoginException('Empty cookie names are not allowed');
        }

        $this->cookie_name = $cookie_name;
    }

    /**
     * Returns login cookiename
     *
     * @return string
     */
    public function getCookieName(): string
    {
        return $this->cookie_name;
    }
}
