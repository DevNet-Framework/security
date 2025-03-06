<?php

/**
 * @author      Mohammed Moussaoui
 * @license     MIT license. For more license information, see the LICENSE file in the root directory.
 * @link        https://github.com/DevNet-Framework
 */

namespace DevNet\Security\Authorization;

class AuthorizationResult
{
    private bool $isSucceeded = true;
    private array $failedRequirements = [];

    public bool $IsSucceeded { get => $this->isSucceeded; }
    public array $FailedRequirements { get => $this->failedRequirements; }

    /**
     * @param array<IAuthorizationRequirement> $failedRequirements
     */
    public function __construct(array $failedRequirements = [])
    {
        if ($failedRequirements) {
            $this->isSucceeded = false;
            $this->failedRequirements = $failedRequirements;
        }
    }
}
