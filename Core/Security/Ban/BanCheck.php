<?php
namespace Core\Security\Ban;

use Core\Data\Connectors\Db\Db;
use Core\Security\AbstractSecurity;

/**
 * BanCheck.php
 *
 * @author Michael "Tekkla" Zorn <tekkla@tekkla.de>
 * @copyright 2016
 * @license MIT
 */
class BanCheck extends AbstractSecurity
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
    private $ip = '';

    /**
     *
     * @var int
     */
    private $ttl_banlog_entry = 300;

    /**
     *
     * @var int
     */
    private $ttl_ban = 600;

    /**
     *
     * @var int
     */
    private $tries = 0;

    /**
     * Constructor
     *
     * @param Db $db
     *            Db connector dependency
     */
    public function __construct(Db $db)
    {
        $this->db = $db;
    }

    /**
     * Sets ip to check
     *
     * @param string $ip
     */
    public function setIp(string $ip, $type = FILTER_FLAG_IPV4)
    {
        if (filter_var($ip, FILTER_VALIDATE_IP, $type) === false) {
            Throw new \Exception(sprintf('"%s" is no valid ip address.'), $ip);
        }

        $this->ip = $ip;
    }

    /**
     * Returns set ip
     *
     * @return string
     */
    public function getIp(): string
    {
        return $this->ip;
    }

    /**
     * Sets the TTL (in seconds) how long a banlog entry stays valid
     *
     * @param int $ttl
     */
    public function setTtlBanLogEntry(int $ttl)
    {
        $this->ttl_banlog_entry = $ttl;
    }

    /**
     * Returns the set TTL (in seconds) of a banlog entry
     *
     * @return int
     */
    public function getTtlBanLogEntry(): int
    {
        return $this->ttl_banlog_entry;
    }

    /**
     * Sets the TTL (in seconds) how long a ban lasts
     *
     * @param int $ttl
     */
    public function setTtlBan(int $ttl)
    {
        $this->duration = $ttl;
    }

    /**
     * Returns the set TTL (in seconds) of how long a ban lasts
     *
     * @return int
     */
    public function getTtlBan(): int
    {
        return $this->ttl_ban;
    }

    /**
     * Sets the number of possible tries before a ban gets active (Default: 0 = never ban)
     *
     * @param int $tries
     */
    public function setTries(int $tries)
    {
        $this->tries = $tries;
    }

    /**
     * Returns the set number of possible tries befor a ban gets active (Default: 0 = never ban)
     *
     * @return int
     */
    public function getTries(): int
    {
        return $this->tries;
    }

    /**
     * Returns the number of ban entires in the log for an IP address within the set duration.
     *
     * @return int
     */
    public function countBanLogEntries(): int
    {
        $this->db->qb([
            'table' => 'core_bans',
            'fields' => 'COUNT(ip)',
            'filter' => 'ip=:ip AND logstamp+:ttl > :expires AND code>0',
            'params' => [
                ':ip' => $this->ip,
                ':ttl' => $this->ttl_banlog_entry,
                ':expires' => time()
            ]
        ]);

        return $this->db->value();
    }

    /**
     * Returns the timestamp from log when ban got active for this ip
     *
     * @return int
     */
    public function getBanActiveTimestamp(): int
    {
        $this->db->qb([
            'table' => 'core_bans',
            'fields' => 'logstamp',
            'filter' => 'ip=:ip AND code=0',
            'params' => [
                ':ip' => $this->ip
            ],
            'order' => 'logstamp DESC',
            'limit' => 1
        ]);

        $data = $this->db->value();

        return $data ? $data : 0;
    }

    public function checkBan()
    {
        // Max tries of 0 before ban means no ban check at all
        if ($this->tries == 0) {
            return false;
        }

        // TTL of zero for log entries means not ban check too
        if ($this->ttl_banlog_entry == 0) {
            return false;
        }

        // Without TTL for bans no bancheck needed
        if ($this->ttl_ban == 0) {
            return false;
        }

        // Further checks do need a set IP address
        if (empty($this->ip)) {
            $this->ip = $_SERVER['REMOTE_ADDR'];
        }

        // No ban if count current tries lies below set max treis
        if ($this->countBanLogEntries() < $this->tries) {
            return false;
        }

        // Do we have an active ban with TTL?
        if ($this->getBanActiveTimestamp() + $this->ttl_ban > time()) {

            if (isset($this->logger)) {
                $this->logger->notice('Access of a banned IP [' . $this->ip . ']');
            }

            return true;
        }

        // Falling through here means to ban the current ip
        $banlog = new BanLogEntry($this->db);
        $banlog->setText('User got banned because of too many tries.');
        $banlog->setCode(0);

        if (isset($this->logger)) {
            $banlog->setLogger($this->logger);
        }

        $banlog->add();

        return true;
    }
}

