<?php

/**
 * @author      Mohammed Moussaoui
 * @license     MIT license. For more license information, see the LICENSE file in the root directory.
 * @link        https://github.com/DevNet-Framework
 */

namespace DevNet\Security\Authentication;

use DevNet\Security\Claims\ClaimsIdentity;
use Exception;

class AuthenticationResult
{   
    private ?ClaimsIdentity $identity = null;
    private ?Exception $error = null;

    public ?ClaimsIdentity $Identity { get => $this->identity; }
    public ?Exception $Error { get => $this->error; }

    public function __construct(object $result)
    {
        if ($result instanceof ClaimsIdentity) {
            $this->identity = $result;
        } else if ($result instanceof Exception) {
            $this->error = $result;
        }
    }

    public function isSucceeded(): bool
    {
        return $this->identity ? true : false;
    }

    public function isFailed(): bool
    {
        return $this->error ? true : false;
    }
}
