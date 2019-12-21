<?php


namespace Niexiawei\Auth\Aspect;

use Niexiawei\Auth\Annotation\CheckUser as Auth;
use Hyperf\Di\Annotation\Aspect;
use Hyperf\Di\Aop\AbstractAspect;
use Hyperf\Di\Aop\ProceedingJoinPoint;
use Hyperf\HttpServer\Contract\ResponseInterface;
use Niexiawei\Auth\AuthInterface;
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
//        $is_auth = true;
//        $methodAnnotation = $proceedingJoinPoint->getAnnotationMetadata()->method;
//        $classAnnotation = $proceedingJoinPoint->getAnnotationMetadata()->class;
//        if(empty($methodAnnotation)){
//            $is_auth = $classAnnotation[Auth::class]->is_auth;
//        }else{
//            $is_auth = $methodAnnotation[Auth::class]->is_auth;
//        }
//        if($is_auth === true){
//            if($this->auth->check()){
//                return $proceedingJoinPoint->process();
//            }else{
//                return $this->response->json(['code'=>401,'msg'=>'你还未登录']);
//            }
//        }else{
//            Context::set(IsAuthInterface::class,false);
//            return $proceedingJoinPoint->process();
//        }
        if($this->auth->check()){
            return $proceedingJoinPoint->process();
        }else{
            return $this->response->json(['code'=>401,'msg'=>'你还未登录']);
        }

    }

}
