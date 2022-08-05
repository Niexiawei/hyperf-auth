<?php

declare(strict_types=1);

namespace Niexiawei\Auth\Middleware;

use Hyperf\HttpServer\Contract\RequestInterface;
use Niexiawei\Auth\AuthInterface;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Hyperf\HttpServer\Contract\ResponseInterface as HttpResponse;

class UserAuthenticationMiddleware implements MiddlewareInterface
{

    protected ContainerInterface $container;
    protected RequestInterface $request;
    protected HttpResponse $response;
    protected AuthInterface $AuthInterface;
    protected int|string $guard;

    public function __construct(ContainerInterface $container, RequestInterface $request, HttpResponse $response)
    {
        $this->container = $container;
        $this->request = $request;
        $this->response = $response;
        $this->AuthInterface = $container->get(AuthInterface::class);
        $this->guard = -1;
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        if (empty($this->AuthInterface->getToken())) {
            return $this->response->json([
                'code' => 401,
                'msg' => 'token不能为空'
            ]);
        }

        try {
            if (!$this->AuthInterface->check()) {
                return $this->response->json(['code' => 401, 'msg' => 'token已失效，请重新登录']);
            }
            if ($this->guard !== -1) {
                if ($this->AuthInterface->guard() !== $this->guard) {
                    return $this->response->json(['code' => 401, 'msg' => '无效的token']);
                }
            }

        } catch (\Throwable $exception) {
            return $this->response->json(['code' => 401, 'msg' => '非法的Token']);
        }
        return $handler->handle($request);
    }
}
