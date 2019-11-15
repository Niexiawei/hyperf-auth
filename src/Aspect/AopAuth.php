<?php


namespace Niexiawei\Auth\Aspect;

use Niexiawei\Auth\Annotation\Auth;
use Hyperf\Di\Annotation\Aspect;
use Hyperf\Di\Aop\AbstractAspect;
use Hyperf\Di\Aop\ProceedingJoinPoint;
use Hyperf\HttpServer\Contract\ResponseInterface;
use Hyperf\Utils\Context;
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

    public function __construct(ContainerInterface $container)
    {
        $this->container = $container;
        $this->response = $container->get(ResponseInterface::class);
    }

    public function process(ProceedingJoinPoint $proceedingJoinPoint)
    {
        if(!empty($classParam = $annotation = $proceedingJoinPoint->getAnnotationMetadata()->class[Auth::class])){
            $annotation = $classParam;
        }else{
            $annotation = $proceedingJoinPoint->getAnnotationMetadata()->method[Auth::class];
        }
        if($annotation->is_auth === true){
            if(\auth()->check()){
                return $proceedingJoinPoint->process();
            }else{
                return $this->response->json(['code'=>401,'msg'=>'你还未登录']);
            }
        }else{
            Context::set('isAuth',false);
            return $proceedingJoinPoint->process();
        }
    }

}