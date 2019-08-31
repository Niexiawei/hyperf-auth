<?php

use Hyperf\Redis\RedisFactory;
use MeigumiI\Auth\Auth as auth;
use Hyperf\Contract\ConfigInterface;
use Hyperf\HttpServer\Contract\RequestInterface;
use Hyperf\Utils\ApplicationContext;
use MeigumiI\Auth\Exception\RedisDBNothingnessException;

if (!function_exists('authRequest')) {
    function authRequest()
    {
        if (!ApplicationContext::hasContainer()) {
            throw new \RuntimeException('The application context lacks the container.');
        }
        $container = ApplicationContext::getContainer();
        if (!$container->has(RequestInterface::class)) {
            throw new \RuntimeException('ConfigInterface is missing in container.');
        }
        return $container->get(RequestInterface::class);
    }
}
if (!function_exists('authConfig')) {
    function authConfig(string $key, $default = null)
    {
        if (!ApplicationContext::hasContainer()) {
            throw new \RuntimeException('The application context lacks the container.');
        }
        $container = ApplicationContext::getContainer();
        if (!$container->has(ConfigInterface::class)) {
            throw new \RuntimeException('ConfigInterface is missing in container.');
        }
        return $container->get(ConfigInterface::class)->get($key, $default);
    }
}

if (!function_exists('authRedis')) {
    function authRedis()
    {
        if (!ApplicationContext::hasContainer()) {
            throw new \RuntimeException('The application context lacks the container.');
        }
        $container = ApplicationContext::getContainer();
        if (!$container->has(\Redis::class)) {
            throw new \RuntimeException('ConfigInterface is missing in container.');
        }
        $redisConfigDB = authConfig('auth.redis_db');

        if(empty($redisConfigDB)){
            $redisConfigDB  = 'default';
        }
        try{
            return $container->get(RedisFactory::class)->get($redisConfigDB);
        }catch (Exception $exception){
            var_dump($exception->getMessage());
            return $container->get(Redis::class);
        }
    }
}

if (!function_exists('auth')) {
    function auth($guard)
    {
        $Auth = new auth();
        return $Auth->auth($guard);
    }
}

if(!function_exists('getClientIp')){
    function getClientIp(){
        $request = authRequest();
        return $request->server('remote_addr');
    }
}

if(!function_exists('getClientAgent')){
    function getClientAgent(){
        $request  = authRequest();
        return $request->server('http_user_agent') ?? 'pc';
    }
}
