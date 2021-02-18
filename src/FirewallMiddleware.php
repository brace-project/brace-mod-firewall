<?php


namespace Brace\Firewall;


use Brace\Core\Base\BraceAbstractMiddleware;
use Brace\Router\RouteMatcher;
use Laminas\Diactoros\Response\TextResponse;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

class FirewallMiddleware extends BraceAbstractMiddleware
{

    /**
     * FirewallMiddleware constructor.
     * @param callable[] $rule
     */
    public function __construct(
        private array $rules,
    ){}

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $reason = "default";
        foreach ($this->rules as $route => $callback) {
            if (RouteMatcher::IsMatching($route, $request, $params, $methods)) {
                $result = phore_di_call($callback, $this->app);
                if ($result === false) {
                    $reason = "Rule: $route";
                    break; // Reject
                }
                if ($result === true) {
                    return $handler->handle($request);
                }
            }
        }
        return $this->app->responseFactory->createResponseWithBody("403 Access denied by firewall ($reason)", 403);
    }
}