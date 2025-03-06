<?php

/**
 * @author      Mohammed Moussaoui
 * @license     MIT license. For more license information, see the LICENSE file in the root directory.
 * @link        https://github.com/DevNet-Framework
 */

namespace DevNet\Security\Claims;

use DevNet\System\Collections\Enumerator;
use DevNet\System\Collections\IEnumerable;
use Closure;

class ClaimsIdentity implements IEnumerable
{
    private ?string $authenticationType;
    private array $claims = [];

    public ?string $AuthenticationType { get => $this->authenticationType; }
    public array $Claims { get => $this->claims; }

    public function __construct(?string $authenticationType = null, array $claims = [])
    {
        $this->authenticationType = $authenticationType;
        $this->claims = $claims;
    }

    public function isAuthenticated(): bool
    {
        return $this->authenticationType ? true : false;
    }

    public function addClaim(Claim $claim)
    {
        $this->claims[spl_object_id($claim)] = $claim;
    }

    public function removeClaim(Claim $claim): bool
    {
        if (isset($this->claims[spl_object_id($claim)])) {
            unset($this->claims[spl_object_id($claim)]);
            return true;
        }

        return false;
    }

    public function hasClaim(string $type, string $value): bool
    {
        foreach ($this->claims as $claim) {
            if ($claim->Type == $type && $claim->Value == $value) {
                return true;
            }
        }

        return false;
    }

    public function findClaim(Closure $predicate): ?Claim
    {
        foreach ($this->claims as $claim) {
            if ($predicate($claim) === true) {
                return $claim;
            }
        }

        return null;
    }

    public function findClaims(Closure $predicate): array
    {
        $claims = [];

        foreach ($this->claims as $claim) {
            if ($predicate($claim) === true) {
                $claims[] = $claim;
            }
        }

        return $claims;
    }

    public function getObjectData(): string
    {
        return serialize($this);
    }

    public function getIterator(): Enumerator
    {
        return new Enumerator($this->claims);
    }
}
