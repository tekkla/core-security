<?php
namespace Core\Security\Token;

use Core\Data\Connectors\Db\Db;

/**
 * AbstractDbToken.php
 *
 * @author Michael "Tekkla" Zorn <tekkla@tekkla.de>
 * @copyright 2016
 * @license MIT
 */
abstract class AbstractDbToken extends AbstractToken
{
    protected $db;

    public function __construct(Db $db)
    {
        $this->db = $db;
    }

}

