<?php


namespace Niexiawei\Auth;

use Hyperf\Contract\ConfigInterface;
use Hyperf\Di\Container;
use Hyperf\HttpServer\Contract\RequestInterface;
use Hyperf\Utils\Context;
use Niexiawei\Auth\Drive\RedisDrive;
use Niexiawei\Auth\Exception\AuthModelNothingnessException;
use Niexiawei\Auth\Exception\NotInheritedInterfaceException;
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

    public function tokenToUser($token){
        $user_info = $this->getStorage()->verify($token);
        $guard = $user_info->guard;
        $model = $this->config->get('auth.guards.' . $guard . '.model');
        $user = $this->getModel($guard)->authFind($user_info->user_id);

        if ($user instanceof $model) {
            return $user;
        }

        throw new \Exception('用户不存在');
    }

    public function getStorage(): DriveInterface
    {

        $drive = $this->config->get('auth.drive', null);
        if (!empty($drive) || $drive instanceof DriveInterface) {
            return make($drive);
        }
    }

    public function refresh(){
        $token = $this->getToken();
        return $this->getStorage()->refresh($token);
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
            return $this->getUserInfo()->guard;
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
        $this->setUserInfo($user_info);
        return true;
    }

    public function id()
    {
        if ($this->check()) {
            return $this->getUserInfo()->user_id;
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

    public function user(): object
    {
        $user = Context::get(UserContextInterface::class, []);
        if ($user) {
            return $user;
        }
        if ($this->check()) {
            if ($this->getUserInfo()->user_id) {
                $guard = $this->getUserInfo()->guard;
                $model = $this->config->get('auth.guards.' . $guard . '.model');
                $user = $this->getModel($guard)->authFind($this->getUserInfo()->user_id);
                if ($user instanceof $model) {
                    Context::set(UserContextInterface::class, $user);
                    return $user;
                }
            }
        }
        throw new \Exception('用户不存在');
    }

    private function getModel($guard): AuthUserInterface
    {
        $model = $this->config->get('auth.guards.' . $guard . '.model');
        if (!class_exists($model)) {
            throw new AuthModelNothingnessException('用户模型不存在' . $model);
        }
        $userModel = new $model;
        if ($userModel instanceof AuthUserInterface) {
            return $userModel;
        }
        throw new NotInheritedInterfaceException('不是AuthUserInterface的实现');
    }


    public function setUserInfo(AuthUserObj $userObj)
    {
        Context::set('auth.user_info', $userObj);
    }

    public function getUserInfo(): ?AuthUserObj
    {
        return Context::get('auth.user_info');
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

    public function formatToken()
    {

    }
}
