<?php
namespace Core\Security\Ban;

use Core\Data\Connectors\Db\Db;
use Core\Security\AbstractSecurity;

/**
 * BanLogEntry.php
 *
 * @author Michael "Tekkla" Zorn <tekkla@tekkla.de>
 * @copyright 2016
 * @license MIT
 */
class BanLogEntry extends AbstractSecurity
{

    /**
     *
     * @var Db
     */
    private $db;

    /**
     *
     * @var int
     */
    private $id_user = 0;

    /**
     *
     * @var string
     */
    private $text;

    /**
     *
     * @var string
     */
    private $logdate;

    /**
     *
     * @var int
     */
    private $logstamp;

    /**
     *
     * @var string
     */
    private $client;

    /**
     *
     * @var string
     */
    private $ip;

    /**
     *
     * @var string
     */
    private $url;

    /**
     *
     * @var string
     */
    private $code;

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
     *
     * @return Db
     */
    public function getDb(): Db
    {
        return $this->db;
    }

    /**
     *
     * @param \Core\Data\Connectors\Db\Db $db
     */
    public function setDb(Db $db)
    {
        $this->db = $db;
    }

    /**
     *
     * @return int
     */
    public function getIdUser(): int
    {
        return $this->id_user;
    }

    /**
     *
     * @param int $id_user
     */
    public function setIdUser(int $id_user)
    {
        $this->id_user = $id_user;
    }

    /**
     *
     * @return string
     */
    public function getText(): string
    {
        return $this->text;
    }

    /**
     *
     * @param string $text
     */
    public function setText(string $text)
    {
        $this->text = $text;
    }

    /**
     *
     * @return string
     */
    public function getLogdate(): string
    {
        return $this->logdate;
    }

    /**
     *
     * @param string $logdate
     */
    public function setLogdate(string $logdate)
    {
        $this->logdate = $logdate;
    }

    /**
     *
     * @return int
     */
    public function getLogstamp(): int
    {
        return $this->logstamp;
    }

    /**
     *
     * @param int $logstamp
     */
    public function setLogstamp(int $logstamp)
    {
        $this->logstamp = $logstamp;
    }

    /**
     *
     * @return string
     */
    public function getClient(): string
    {
        return $this->client;
    }

    /**
     *
     * @param string $client
     */
    public function setClient(string $client)
    {
        $this->client = $client;
    }

    /**
     *
     * @return string
     */
    public function getIp(): string
    {
        return $this->ip;
    }

    /**
     *
     * @param string $ip
     */
    public function setIp(string $ip)
    {
        $this->ip = $ip;
    }

    /**
     *
     * @return string
     */
    public function getUrl(): string
    {
        return $this->url;
    }

    /**
     *
     * @param string $url
     */
    public function setUrl(string $url)
    {
        $this->url = $url;
    }

    /**
     * Returns banlog code
     *
     * @return int
     */
    public function getCode(): int
    {
        return $this->code;
    }

    /**
     * Sets banlog code
     *
     * 0 = Notice
     * 1 = Banable event
     * 2 = Enty activates ban
     *
     * @param int $code
     */
    public function setCode(int $code)
    {
        $allowed_codes = [
            0,
            1,
            2
        ];

        if (!in_array($code, $allowed_codes)) {
            $code = 1;
        }

        $this->code = $code;
    }

    /**
     * Creates log entry in Db and return log id
     *
     * @return int
     */
    public function add(): int
    {
        if (empty($this->logdate) || empty($this->logstamp)) {

            $time = time();

            if (empty($this->logdate)) {
                $this->logdate = date('Y-m-d H:i:s', $time);
            }

            if (empty($this->logstamp)) {
                $this->logstamp = $time;
            }
        }

        if (empty($this->client)) {
            $this->client = $_SERVER['HTTP_USER_AGENT'];
        }

        if (empty($this->ip)) {
            $this->ip = $_SERVER['REMOTE_ADDR'];
        }

        if (empty($this->url)) {
            $this->url = $_SERVER['REQUEST_URI'];
        }

        $this->db->qb([
            'table' => 'core_bans',
            'data' => [
                'text' => $this->text,
                'logdate' => $this->logdate,
                'logstamp' => $this->logstamp,
                'client' => $this->client,
                'ip' => $this->ip,
                'url' => $this->url,
                'id_user' => $this->id_user,
                'code' => $this->code
            ]
        ], true);

        return $this->db->lastInsertId();
    }
}
