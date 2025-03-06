<?php

/**
 * @author      Mohammed Moussaoui
 * @license     MIT license. For more license information, see the LICENSE file in the root directory.
 * @link        https://github.com/DevNet-Framework
 */

namespace DevNet\Security\Authorization;

use DevNet\System\Async\Task;

class ClaimsRequirement implements IAuthorizationRequirement, IAuthorizationHandler
{
    protected string $claimType;
    protected array $allowedValues;

    public string $ClaimType { get => $this->claimType; }
    public array $AllowedValues { get => $this->allowedValues; }

    public function __construct(string $claimType, array $allowedValues = [])
    {
        $this->claimType = $claimType;
        $this->allowedValues = $allowedValues;
    }

    public function getHandler(): IAuthorizationHandler
    {
        return $this;
    }

    public function Handle(AuthorizationContext $context): Task
    {
        $user = $context->User;
        if ($user) {
            if ($this->allowedValues) {
                $found = $user->findClaims(fn ($claim) =>(strtolower($claim->Type) == strtolower($this->claimType)
                && in_array($claim->Value, $this->allowedValues)));
            } else {
                $found = $user->findClaims(fn ($claim) => strtolower($claim->Type) == strtolower($this->claimType));
            }

            if ($found) {
                $context->succeed($this);
            }
        }

        return Task::completedTask();
    }
}
