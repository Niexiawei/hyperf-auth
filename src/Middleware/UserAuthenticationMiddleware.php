<?php

declare(strict_types=1);

namespace Niexiawei\Auth\Middleware;

use Hyperf\HttpServer\Contract\RequestInterface;
use Hyperf\Utils\ApplicationContext;
use Niexiawei\Auth\AuthInterface;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Hyperf\HttpServer\Contract\ResponseInterface as HttpResponse;

class UserAuthenticationMiddleware implements MiddlewareInterface
{
    /**
     * @var ContainerInterface
     */
    protected $container;
    protected $request;
    protected $response;
    protected $AuthInterface;
    public function __construct(ContainerInterface $container,RequestInterface $request,HttpResponse $response)
    {
        $this->container = $container;
        $this->request = $request;
        $this->response = $response;
        $this->AuthInterface = $container->get(AuthInterface::class);
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {

        if(empty($this->AuthInterface->getToken())){
            return  $this->response->json([
               'code'=>401,
               'msg'=>'token不能为空'
            ]);
        }

        try{
            if(!auth($this->guard())->check()){
                return  $this->response->json(['code'=>401,'msg'=>'token已失效，请重新登录']);
            }
        }catch (\Throwable $exception){
            return  $this->response->json(['code'=>401,'msg'=>'非法的Token']);
        }
        return $handler->handle($request);
    }
    private function guard(){
        $user_info = $this->AuthInterface->formatToken();
        return $user_info['guard'] ?? '';
    }
}