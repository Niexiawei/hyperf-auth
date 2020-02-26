<?php


namespace Niexiawei\Auth;

use Hyperf\Contract\ConfigInterface;
use Hyperf\Di\Container;
use Hyperf\HttpServer\Contract\RequestInterface;
use Hyperf\Utils\Context;
use Niexiawei\Auth\Exception\AuthModelNothingnessException;
use Swoole\Exception;

class Auth implements AuthInterface
{
    private $container;
    private $request;
    private $config;

    public function __construct(Container $container)
    {
        $this->container = $container;
        $this->request = $container->get(RequestInterface::class);
        $this->config = $container->get(ConfigInterface::class);
    }

    public function getStorage(): StorageInterface
    {
        $drive = $this->config->get('auth.drive','kv');
        switch ($drive) {
            case 'kv':
                return make(StorageRedis::class);
                break;
            case 'sort_set':
                return make(StorageRedisToSortedSet::class);
                break;
            default:
                throw new Exception('驱动不存在');
                break;
        }
    }

    public function login(string $guard, object $user)
    {
        return $this->getStorage()->generate($guard, $user->id);
    }

    public function setAllowRefreshToken(bool $allow = true): Auth
    {
        Context::set(AllowRefreshOrNotInterface::class, $allow);
        return $this;
    }

    public function setTTL(int $second): Auth
    {
        if ($second <= 10) {
            throw new \Exception('token时间必须大于10秒');
        }
        $res = Context::set(setTokenExpireInterface::class, $second);
        return $this;
    }

    public function guard()
    {
        if ($this->check()) {
            return Context::get('user_info')['guard'];
        }
        return '';
    }

    public function check()
    {
        $token = $this->getToken();
        if (empty($token)) {
            return false;
        }
        $user_info = $this->getStorage()->verify($token);
        if (empty($user_info)) {
            return false;
        }
        Context::set('user_info', $user_info);
        return true;
    }

    public function id()
    {
        if ($this->check()) {
            return Context::get('user_info')['uid'];
        }
        return 0;
    }

    public function logout(): bool
    {
        if (!$this->check()) {
            return false;
        }
        $this->getStorage()->delete($this->getToken());
        return true;
    }

    public function user():object
    {
        $id = $this->id();
        if ($id > 0) {
            $guard = $this->formatToken()['guard'];
            $model = $this->config->get('auth.guards.' . $guard . '.model');
            $user =  $this->getModel($guard)->find($id);
            if($user instanceof $model){
                return $user;
            }
        }
        throw new \Exception('用户不存在');
    }

    private function getModel($guard): object
    {
        $model = $this->config->get('auth.guards.' . $guard . '.model');
        if (!class_exists($model)) {
            throw new AuthModelNothingnessException('用户模型不存在' . $model);
        }
        return new $model;

    }

    public function formatToken()
    {
        return $this->getStorage()->formatToken($this->getToken());
    }

    public function getToken()
    {
        if (!empty(Context::get('token'))) {
            return Context::get('token');
        }
        if ($this->request->has('token')) {
            $token = $this->request->input('token');
        } elseif ($this->request->hasHeader('token')) {
            $token = $this->request->header('token');
        } else {
            $token = '';
        }
        Context::set('token', $token);
        return $token;
    }

    public function setToken($token): Auth
    {
        Context::set('token', $token);
        return $this;
    }
}
