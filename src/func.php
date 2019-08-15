<?php

use MeigumiI\Auth\Auth as auth;
use Hyperf\Contract\ConfigInterface;
use Hyperf\HttpServer\Contract\RequestInterface;
use Hyperf\Utils\ApplicationContext;

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
        return $container->get(\Redis::class);
    }
}

if (!function_exists('auth')) {
    function auth($guard)
    {
        $Auth = new auth();
        return $Auth->auth($guard);
    }
}
