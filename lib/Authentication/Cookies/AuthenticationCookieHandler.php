<?php

/**
 * @author      Mohammed Moussaoui
 * @license     MIT license. For more license information, see the LICENSE file in the root directory.
 * @link        https://github.com/DevNet-Framework
 */

namespace DevNet\Security\Authentication\Cookies;

use DevNet\System\TimeSpan;
use DevNet\Security\Session;
use DevNet\Security\Authentication\AuthenticationResult;
use DevNet\Security\Authentication\IAuthenticationHandler;
use DevNet\Security\Authentication\IAuthenticationSigningHandler;
use DevNet\Security\Claims\ClaimsIdentity;
use Exception;

class AuthenticationCookieHandler implements IAuthenticationHandler, IAuthenticationSigningHandler
{
    private AuthenticationCookieOptions $options;
    private Session $session;

    public AuthenticationCookieOptions $Options { get => $this->options; }
    public Session $Session { get => $this->session; }

    public function __construct(AuthenticationCookieOptions $options)
    {
        $this->options = $options;
        $this->session = new Session($options->CookieName, $options->CookiePath);

        if (!$this->options->ExpireTime) {
            $this->options->ExpireTime = new TimeSpan();
        }
    }

    public function authenticate(): AuthenticationResult
    {
        if ($this->session->isSet()) {
            $this->session->start();
            $identity = $this->session->get(ClaimsIdentity::class);

            if ($identity) {
                return new AuthenticationResult($identity);
            }
        }

        return new AuthenticationResult(new Exception("Session cookie dose not have ClaimsIdentity data"));
    }

    public function signIn(ClaimsIdentity $user, bool $isPersistent = false): void
    {
        if ($isPersistent) {
            $this->session->setOptions(['cookie_lifetime' => (int) $this->options->ExpireTime->TotalSeconds]);
        } else {
            $this->session->setOptions(['cookie_lifetime' => 0]);
        }

        $this->session->start();
        $this->session->set(ClaimsIdentity::class, $user);
    }

    public function signOut(): void
    {
        $this->session->destroy();
    }
}
