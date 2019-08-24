<?php

declare(strict_types=1);

namespace MeigumiI\Auth\Middleware;

use Hyperf\HttpServer\Contract\RequestInterface;
use MeigumiI\Auth\Auth;
use MeigumiI\Auth\Exception\GuardNothingnessException;
use MeigumiI\Auth\TokenAuthTools;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Hyperf\HttpServer\Contract\ResponseInterface as HttpResponse;

class authCheck implements MiddlewareInterface
{
    /**
     * @var ContainerInterface
     */
    protected $container;
    protected $request;
    protected $response;
    public function __construct(ContainerInterface $container,RequestInterface $request,HttpResponse $response)
    {
        $this->container = $container;
        $this->request = $request;
        $this->response = $response;
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {

        if(empty($this->getToken())){
            return  $this->response->json([
               'code'=>401,
               'msg'=>'token不能为空'
            ]);
        }

        try{
            if(!auth($this->guard())->check()){
                return  $this->response->json(['code'=>401,'msg'=>'token已失效，请重新登录']);
            }
        }catch (GuardNothingnessException $exception){
            return  $this->response->json(['code'=>401,'msg'=>'非法的Token']);
        }

        return $handler->handle($request);
    }

    public function getToken(){
        $auth = new Auth();
        return $auth->getToken();
    }

    public function guard(){
        $tools = new TokenAuthTools();
        $raw = $tools->formatToken($this->getToken());
        if(isset($raw['guard'])){
            return $raw['guard'];
        }else{
            return false;
        }
    }
}