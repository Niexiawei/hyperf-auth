<?php


namespace Niexiawei\Auth;

use Hyperf\Contract\ConfigInterface;
use Hyperf\Di\Container;
use Hyperf\HttpServer\Contract\RequestInterface;
use Hyperf\Utils\Context;
use Niexiawei\Auth\Exception\AuthModelNothingnessException;

class Auth
{
    private $container;
    private $request;
    private $config;
    private $storage;
    public function __construct(Container $container)
    {
        $this->container = $container;
        $this->request = $container->get(RequestInterface::class);
        $this->config = $container->get(ConfigInterface::class);
        $this->storage = $container->get(StorageRedisInterface::class);
    }

    public function auth($guard)
    {
        //return new TokenAuthDrive($guard, $this->getToken(), $this->getModel($guard));
        Context::set('guard',$guard);
        Context::set('token',$this->getToken());
        return $this;
    }

    public function login(object $user){
        return $this->storage->generate(Context::get('guard'),$user->id);
    }

    public function check(){
        $user_info = $this->storage->verify(Context::get('token'));
        Context::set('user_info',$user_info);
        if(empty($user_info)){
            return false;
        }
        return true;
    }

    public function id(){
        if($this->check()){
            return Context::get('user_info')['id'];
        }
        return 0;
    }

    public function logout():bool
    {
        $this->storage->delete(Context::get('token'));
        return true;
    }

    public function user(){
        $id = $this->id();
        if($id > 0){
            return $this->getModel(Context::get('guard'))->find($id);
        }
        return [];
    }

    private function getModel($guard): object
    {
        try{
            $model = $this->config->get('auth.guards.' . $guard . '.model');
            return new $model;
        }catch (\Exception $exception){
            throw new AuthModelNothingnessException('用户模型不存在');
        }

    }

    public function formatToken(){
        return $this->storage->formatToken($this->getToken());
    }

    public function getToken()
    {
        if ($this->request->has('token')) {
            return $this->request->input('token');
        } elseif ($this->request->hasHeader('token')) {
            return $this->request->header('token');
        } else {
            return '';
        }
    }
}