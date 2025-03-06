<?php

/**
 * @author      Mohammed Moussaoui
 * @license     MIT license. For more license information, see the LICENSE file in the root directory.
 * @link        https://github.com/DevNet-Framework
 */

namespace DevNet\Security\Authorization;

use DevNet\Security\Claims\ClaimsIdentity;

class AuthorizationContext
{
    private ?ClaimsIdentity $user = null;
    private array $requirements = [];
    private array $pendingRequirements = [];
    private array $failedRequirements = [];

    public ?ClaimsIdentity $User { get => $this->user; }
    public array $Requirements { get => $this->requirements; }
    public array $PendingRequirements { get => $this->pendingRequirements; }
    public array $FailedRequirements { get => $this->failedRequirements; }

    public function __construct(array $requirements = [], ?ClaimsIdentity $user = null)
    {
        $this->user = $user;
        $this->requirements = $requirements;
        foreach ($requirements as $requirement) {
            $this->pendingRequirements[spl_object_id($requirement)] = $requirement;
        }
    }

    public function fail(?IAuthorizationRequirement $requirement = null): void
    {
        if (isset($this->pendingRequirements[spl_object_id($requirement)])) {
            unset($this->pendingRequirements[spl_object_id($requirement)]);
            $this->failedRequirements[] = $requirement;
        }
    }

    public function succeed(IAuthorizationRequirement $requirement): void
    {
        if (isset($this->pendingRequirements[spl_object_id($requirement)])) {
            unset($this->pendingRequirements[spl_object_id($requirement)]);
        }
    }

    public function getResult(): AuthorizationResult
    {
        $failedRequirements = $this->failedRequirements;
        foreach ($this->pendingRequirements as $requirement) {
            $failedRequirements[] = $requirement;
        }
        
        // Failure result
        if ($failedRequirements) {
            return new AuthorizationResult($failedRequirements);
        }

        // Succeeded result.
        return new AuthorizationResult();
    }
}
