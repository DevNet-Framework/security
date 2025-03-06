<?php

/**
 * @author      Mohammed Moussaoui
 * @license     MIT license. For more license information, see the LICENSE file in the root directory.
 * @link        https://github.com/DevNet-Framework
 */

namespace DevNet\Security\Authorization;

class AuthorizationPolicy
{
    private string $name;
    private array $requirements;

    public string $Name { get => $this->name; }
    public array $Requirements { get => $this->requirements; }

    public function __construct(string $name, array $requirements)
    {
        $this->name = $name;
        $this->requirements = $requirements;
    }
}
