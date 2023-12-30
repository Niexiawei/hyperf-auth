<?php


namespace Niexiawei\Auth\Aspect;

use Hyperf\Di\Annotation\Aspect;
use Hyperf\Di\Aop\AbstractAspect;
use Hyperf\Di\Aop\ProceedingJoinPoint;
use Hyperf\HttpServer\Contract\ResponseInterface;
use Niexiawei\Auth\Annotation\Auth;
use Niexiawei\Auth\AuthInterface;
use Niexiawei\Auth\Exception\TokenInvalidException;
use Niexiawei\Auth\Exception\TokenUnableToRefreshException;
use Psr\Container\ContainerInterface;

#[Aspect()]
class AuthAspect extends AbstractAspect
{
    public array $annotations = [
        Auth::class
    ];

    public ContainerInterface $container;
    public ResponseInterface $response;
    public AuthInterface $auth;

    public function __construct(ContainerInterface $container)
    {
        $this->container = $container;
        $this->response = $container->get(ResponseInterface::class);
        $this->auth = $container->get(AuthInterface::class);
    }

    public function process(ProceedingJoinPoint $proceedingJoinPoint)
    {
        $this->auth->check();
        return $proceedingJoinPoint->process();
    }
}
