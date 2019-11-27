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
    public function login(string $guard,object $user){
        return $this->storage->generate($guard,$user->id);
    }

    public function check(){
        $token = $this->getToken();
        if(empty($token)){
            return false;
        }
        $user_info = $this->storage->verify($token);
        if(empty($user_info)){
            return false;
        }
        Context::set('user_info',$user_info);
        return true;
    }

    public function id(){
        if($this->check()){
            return Context::get('user_info')['uid'];
        }
        return 0;
    }

    public function logout():bool
    {
        if(!$this->check()){
            return  false;
        }
        $this->storage->delete($this->getToken());
        return true;
    }

    public function user(){
        $id = $this->id();
        if($id > 0){
            $guard = $this->formatToken()['guard'];
            return $this->getModel($guard)->find($id);
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
        if(!empty(Context::get('token'))){
            return Context::get('token');
        }
        if ($this->request->has('token')) {
            $token =  $this->request->input('token');
        } elseif ($this->request->hasHeader('token')) {
            $token = $this->request->header('token');
        } else {
            $token = '';
        }
        Context::set('token',$token);
        return $token;
    }
}