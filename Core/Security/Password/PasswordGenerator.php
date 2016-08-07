<?php
namespace Core\Security\Password;

/**
 * PasswordGenerator.php
 *
 * @author Michael "Tekkla" Zorn <tekkla@tekkla.de>
 * @copyright 2016
 * @license MIT
 *
 * This class combines two ideas for randowm password generation from GistHub and Paragon Initiative
 *
 * @see https://gist.github.com/tylerhall/521810
 * @see https://paragonie.com/blog/2015/07/how-safely-generate-random-strings-and-integers-in-php#random-str
 */
class PasswordGenerator
{

    /**
     *
     * @var int
     */
    private $length = 9;

    /**
     *
     * @var string
     */
    private $charsets_to_use = 'luds';

    /**
     *
     * @var string
     */
    private $password = '';

    /**
     *
     * @var string
     */
    private $lowercase = 'abcdefghjkmnpqrstuvwxyz';

    /**
     *
     * @var string
     */
    private $uppercase = 'ABCDEFGHJKMNPQRSTUVWXYZ';

    /**
     *
     * @var string
     */
    private $decimals = '23456789';

    /**
     *
     * @var string
     */
    private $specialchars = '!@#$%&*?';

    /**
     * Sets password length
     *
     * @param int $length
     *
     * @throws PasswordException
     */
    public function setLength(int $length)
    {
        if ($length < 1) {
            throw new PasswordException('Length must be a positive integer.');
        }

        $this->length = $length;
    }

    /**
     * Selects the charactersets to use in password generation
     *
     * @param unknown $charsets_to_use
     *            The following sets are possible:
     *
     *            l = lowercase chars (Default: abcdefghjkmnpqrstuvwxyz)
     *            u = uppercase chars (Default: ABCDEFGHJKMNPQRSTUVWXYZ)
     *            d = decimals (Default: 23456789)
     *            s = specialchars (Default: !@#$%&*?)
     *
     *            Example: 'lds' stands for a password to generate out of lowercase chars, decimals and spechialchars
     */
    public function setCharsetsToUse(string $charsets_to_use)
    {
        if (!preg_match("/[^luds]/", $charsets_to_use)) {
            Throw new PasswordException('No valid charset tu use set. Please select one or more sets out of "luds"');
        }

        $this->charsets_to_use = $charsets_to_use;
    }

    /**
     * Sets a list of lowercase chars to be used in password generator
     *
     * @param string $lowercase_chars
     * @throws PasswordException
     */
    public function setLowercaseChars(string $lowercase_chars)
    {
        if (empty($lowercase_chars)) {
            Throw new PasswordException('Lovercase chars cannot be an empty string.');
        }

        $this->lowercase = $lowercase_chars;
    }

    /**
     * Sets a list of uppercase chars to be used in password generator
     *
     * @param string $uppercase_chars
     *
     * @throws PasswordException
     */
    public function setUppercaseChars(string $uppercase_chars)
    {
        if (empty($uppercase_chars)) {
            Throw new PasswordException('Uppercase chars cannot be an empty string.');
        }

        $this->uppercase = $uppercase_chars;
    }

    /**
     * Sets a list of decimal to be used in password generator
     *
     * @param string $numbers
     *
     * @throws PasswordException
     */
    public function setDecimals(string $decimals)
    {
        if (empty($decimals)) {
            Throw new PasswordException('Decimals cannot be an empty string.');
        }

        $this->decimals = $decimals;
    }

    /**
     * Sets a list of specialchars to be used in password generator
     *
     * @param string $special_chars
     *
     * @throws PasswordException
     */
    public function setSpecialchars(string $specialchars)
    {
        if (empty($specialchars)) {
            Throw new PasswordException('Specialchars cannot be an empty string.');
        }

        $this->specialchars = $specialchars;
    }

    /**
     * Returns the generated password
     *
     * @return string
     */
    public function getPassword(): string
    {
        return $this->password ?? $this->generate();
    }

    /**
     * Generates random password and returns it
     *
     * @return string
     */
    public function generate()
    {
        $alphabet = '';

        if (strpos($this->available_sets, 'l') !== false) {
            $alphabet .= $this->lowercase;
        }

        if (strpos($this->available_sets, 'u') !== false) {
            $alphabet .= $this->uppercase;
        }

        if (strpos($this->available_sets, 'd') !== false) {
            $alphabet .= $this->numbers;
        }

        if (strpos($this->available_sets, 's') !== false) {
            $alphabet .= $this->special_chars;
        }

        $alphamax = strlen($alphabet) - 1;

        if ($alphamax < 1) {
            throw new PasswordException('Invalid alphabet');
        }

        $this->password = '';

        for ($i = 0; $i < $this->length; ++$i) {
            $this->password .= $alphabet[random_int(0, $alphamax)];
        }

        return $this->password;
    }
}

