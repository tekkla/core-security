<?php
namespace Core\Security\Token;

/**
 * RemoveExpiredTokensTrait.php
 *
 * @author Michael "Tekkla" Zorn <tekkla@tekkla.de>
 * @copyright 2016
 * @license MIT
 */
trait RemoveExpiredTokensTrait {

    public function removeExpiredTokens()
    {
        if (!isset($this->db)) {
            Throw new TokenException('Can not clean expired tokens without a valid Db connector.');
        }

        $token_tables = [
            'core_activation_tokens',
            'core_auth_tokens'
        ];

        foreach ($token_tables as $table) {
            $this->db->delete($table, 'expires < :time', [
                'time' => date('Y-m-d H:i:s')
            ]);
        }
    }
}

