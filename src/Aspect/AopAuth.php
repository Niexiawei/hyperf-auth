<?php


namespace Niexiawei\Auth\Aspect;

use Niexiawei\Auth\Annotation\CheckUser as Auth;
use Hyperf\Di\Annotation\Aspect;
use Hyperf\Di\Aop\AbstractAspect;
use Hyperf\Di\Aop\ProceedingJoinPoint;
use Hyperf\HttpServer\Contract\ResponseInterface;
use Hyperf\Utils\Context;
use Niexiawei\Auth\AuthInterface;
use Niexiawei\Auth\IsAuthInterface;
use Psr\Container\ContainerInterface;

/**
 * Class AopAuth
 * @package App\Aspect
 * @Aspect()
 */

class AopAuth extends AbstractAspect
{
    public $annotations= [
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
        var_dump($proceedingJoinPoint->className);
        var_dump($proceedingJoinPoint->methodName);
        if(!empty($classParam = $proceedingJoinPoint->getAnnotationMetadata()->class)){
            $annotation = $proceedingJoinPoint->getAnnotationMetadata()->class[Auth::class];
        }else{
            $annotation = $proceedingJoinPoint->getAnnotationMetadata()->method[Auth::class];
        }
        if($annotation->is_auth === true){
            if($this->auth->check()){
                return $proceedingJoinPoint->process();
            }else{
                return $this->response->json(['code'=>401,'msg'=>'你还未登录']);
            }
        }else{
            Context::set(IsAuthInterface::class,false);
            return $proceedingJoinPoint->process();
        }
    }

}