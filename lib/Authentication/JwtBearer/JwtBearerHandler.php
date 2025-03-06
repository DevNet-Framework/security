<?php

/**
 * @author      Mohammed Moussaoui
 * @license     MIT license. For more license information, see the LICENSE file in the root directory.
 * @link        https://github.com/DevNet-Framework
 */

namespace DevNet\Security\Authentication\JwtBearer;

use DevNet\Security\Authentication\AuthenticationResult;
use DevNet\Security\Authentication\IAuthenticationHandler;
use DevNet\Security\Tokens\Jwt\JwtSecurityTokenHandler;
use Exception;

class JwtBearerHandler implements IAuthenticationHandler
{
    private JwtBearerOptions $options;
    private JwtSecurityTokenHandler $handler;

    public JwtBearerOptions $Options { get => $this->options; }

    public function __construct(JwtBearerOptions $options)
    {
        $this->options = $options;
        $this->handler = new JwtSecurityTokenHandler();
    }

    public function readToken(): string
    {
        $headers = getallheaders();;
        $bearerToken = $headers['Authorization'];
        if (!$bearerToken) {
            throw new Exception("The request is missing the authorization header!");
        }

        if (!preg_match("/^Bearer\s+(.*)$/", $bearerToken[0], $matches)) {
            throw new Exception("Incorrect authentication header scheme!");
        }

        return $matches[1];
    }

    public function authenticate(): AuthenticationResult
    {
        try {
            $token = $this->readToken();
            $jwtToken = $this->handler->validateToken($token, $this->Options->SecurityKey, $this->Options->Issuer, $this->Options->Audience);
            return new AuthenticationResult($jwtToken->Payload->Claims);
        } catch (\Throwable $exception) {
            return new AuthenticationResult($exception);
        }
    }
}
