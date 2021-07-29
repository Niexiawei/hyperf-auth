<?php


namespace Niexiawei\Auth\Aspect;

use Hyperf\Di\Annotation\Aspect;
use Hyperf\Di\Aop\AbstractAspect;
use Hyperf\Di\Aop\ProceedingJoinPoint;
use Hyperf\HttpServer\Contract\ResponseInterface;
use Niexiawei\Auth\Annotation\Auth;
use Niexiawei\Auth\AuthInterface;
use Psr\Container\ContainerInterface;

/**
 * Class AopAuth
 * @package App\Aspect
 * @Aspect()
 */
class AuthAspect extends AbstractAspect
{
    public $annotations = [
        Auth::class
    ];

    public $container;
    public $response;
    public $auth;

    public function __construct(ContainerInterface $container)
    {
        $this->container = $container;
        $this->response = $container->get(ResponseInterface::class);
        $this->auth = $container->get(AuthInterface::class);
    }

    public function process(ProceedingJoinPoint $proceedingJoinPoint)
    {
        try {
            $this->auth->check();
            return $proceedingJoinPoint->process();
        } catch (\Throwable $exception) {
            return $this->response->json(['code' => 401, 'msg' => $exception->getMessage()]);
        }
    }
}
