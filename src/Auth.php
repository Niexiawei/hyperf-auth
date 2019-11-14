<?php


namespace Niexiawei\Auth;

use Hyperf\Di\Container;
use Niexiawei\Auth\Exception\AuthModelNothingnessException;

class Auth
{
    private $container;

    public function __construct(Container $container)
    {
        $this->container = $container;
    }

    public function auth($guard)
    {
        return new TokenAuthDrive($guard, $this->getToken(), $this->getModel($guard));
    }

    public function getModel($guard): object
    {
        try{
            $model = authConfig('auth.guards.' . $guard . '.model');
            $object = new $model;
            if (empty($object)){
                throw new AuthModelNothingnessException('用户模型不存在');
            }
            return  $object;
        }catch (\Exception $exception){
            throw new AuthModelNothingnessException('用户模型不存在');
        }

    }

    public function getToken()
    {
        $request = authRequest();
        if ($request->has('token')) {
            return $request->input('token');
        } elseif ($request->hasHeader('token')) {
            return $request->header('token');
        } else {
            return '';
        }
    }
}