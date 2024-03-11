<?php

/**
 * @author      Mohammed Moussaoui
 * @license     MIT license. For more license information, see the LICENSE file in the root directory.
 * @link        https://github.com/DevNet-Framework
 */

namespace DevNet\Security\Authorization;

use DevNet\Security\Claims\ClaimsIdentity;

interface IAuthorization
{
    public function authorize(ClaimsIdentity $user, ?string $policyName): AuthorizationResult;
}
