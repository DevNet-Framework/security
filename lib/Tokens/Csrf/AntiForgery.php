<?php

/**
 * @author      Mohammed Moussaoui
 * @license     MIT license. For more license information, see the LICENSE file in the root directory.
 * @link        https://github.com/DevNet-Framework
 */

namespace DevNet\Security\Tokens\Csrf;

class AntiForgery implements IAntiForgery
{
    private AntiForgeryOptions $options;
    private AntiForgeryTokenStore $store;

    public AntiForgeryOptions $Options { get => $this->options; }

    public function __construct(AntiForgeryOptions $options)
    {
        $this->options = $options;
        $this->store   = new AntiForgeryTokenStore($options);
    }

    public function getToken(): AntiForgeryToken
    {
        $token = $this->store->getCookieToken();
        if ($token) {
            return $token;
        }

        $token = new AntiForgeryToken();
        $this->store->saveCookieToken($token);
        return $token;
    }

    public function validateToken(string $token): bool
    {
        if ($this->getToken() == $token) {
            return true;
        }

        return false;
    }
}
