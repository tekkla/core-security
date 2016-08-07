<?php
namespace Core\Security\Password;

/**
 * HashGenerator.php
 *
 * @author Michael "Tekkla" Zorn <tekkla@tekkla.de>
 * @copyright 2016
 * @license MIT
 */
class HashGenerator
{

    /**
     *
     * @var string
     */
    private $password;

    /**
     *
     * @var string
     */
    private $salt = '@m@rschH@ngtDerH@mmer1234';

    /**
     *
     * @var string
     */
    private $hash;

    /**
     *
     * @var string
     */
    private $regex;

    /**
     * Constructor
     *
     * @param string $password
     */
    public function __construct(string $password)
    {
        if (empty($password)) {
            Throw new PasswordException('Please provide a password.');
        }

        $this->password = $password;
    }

    /**
     * Sets the password
     *
     * @param string $password
     */
    public function setPassword(string $password)
    {
        $this->password = $password;
    }

    /**
     * Returns the set password
     *
     * @return string
     */
    public function getPassword(): string
    {
        return $this->password;
    }

    /**
     * Sets a salt
     *
     * @param string $salt
     */
    public function setSalt(string $salt)
    {
        $this->salt = $salt;
    }

    /**
     * Returns set salt
     *
     * @return string
     */
    public function getSalt(): string
    {
        return $this->salt;
    }

    /**
     * Returns a hash
     *
     * @return string
     */
    public function getHash(): string
    {
        if (empty($this->hash)) {
            $this->createHash();
        }

        return $this->hash;
    }

    /**
     * Sets a regular expression which gets used to validate the password against it
     *
     * @param string $regex
     */
    public function setRegex(string $regex)
    {
        $this->regex = $regex;
    }

    /**
     * Checks the password agains the set regex and returns the boolean result of this check
     *
     * @return bool
     */
    public function checkPassword(): bool
    {
        if (!isset($this->regex)) {
            return true;
        }

        return filter_var($this->password, FILTER_VALIDATE_REGEXP, [
            'options' => [
                'regexp' => $this->regex
            ]
        ]);
    }

    /**
     * Creates a hash by combining the set password with
     *
     * @param int $algo
     * @param array $options
     * @return string
     */
    public function generate(int $algo = PASSWORD_DEFAULT, array $options = null): string
    {
        if ($this->checkPassword() ===false) {
            Throw new PasswordException('The set password does not meet the requirements of the set regular expression');
        }

        if (isset($options)) {
            $this->hash = password_hash($this->password . $this->salt, $options);
        }
        else {
            $this->hash = password_hash($this->password . $this->salt, $algo);
        }

        return $this->hash;
    }
}

