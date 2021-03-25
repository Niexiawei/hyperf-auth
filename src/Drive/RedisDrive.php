<?php

namespace Niexiawei\Auth\Drive;


use Carbon\Carbon;
use Hyperf\Contract\ConfigInterface;
use Hyperf\Di\Annotation\Inject;
use Hyperf\Redis\RedisFactory;
use Hyperf\Utils\Context;
use Niexiawei\Auth\Constants\AllowRefreshOrNotInterface;
use Niexiawei\Auth\AuthUserObj;
use Niexiawei\Auth\DriveInterface;
use Niexiawei\Auth\Exception\TokenUnableToRefreshException;
use Niexiawei\Auth\Constants\setTokenExpireInterface;
use Niexiawei\Auth\Util;

class RedisDrive implements DriveInterface
{
    /**
     * @Inject()
     * @var RedisFactory
     */
    protected $RedisFactory;
    /**
     * @Inject()
     * @var ConfigInterface
     */
    protected $config;

    /**
     * @Inject()
     * @var Util
     *
     */
    protected $util;

    public $user_token_list = 'user_token_list';

    public function config($key, $default = '')
    {
        return $this->config->get('auth.' . $key, $default);
    }

    /**
     * @return \Hyperf\Redis\RedisProxy|\Redis
     * 获取Redis
     */

    protected function redis()
    {
        $pool = $this->config('redis_pool', 'default');
        return $this->RedisFactory->get($pool);
    }

    private function maxLoginNum(AuthUserObj $userObj): int
    {
        $gurad = $userObj->guard;
        $config = $this->config('guards.' . $gurad);
        if (isset($config['max_login_num'])) {
            return $config['max_login_num'];
        }
        return $this->config('max_login_num', 7);
    }

    private function getTTL()
    {
        $config = $this->config('expire', 3600 * 24);
        $second = Context::get(setTokenExpireInterface::class, $config);
        return $second;
    }

    public function getUidTokens(AuthUserObj $userObj)
    {
        $tokens = [];
        $search = $userObj->user_id . ':' . $userObj->guard . '_*';
        $it = null;
        while (true) {
            $arr = $this->redis()->hScan($this->user_token_list, $it, $search);
            if ($arr === false) {
                break;
            }
            foreach ($arr as $key => $value) {
                $value = unserialize($value);
                if ($value instanceof AuthUserObj) {
                    $tokens[] = [$key, Carbon::parse($value->expire_date)->getTimestamp()];
                }
            }
        }
        return $tokens;
    }

    public function delSurplusToken(AuthUserObj $userObj)
    {
        $tokens = $this->getUidTokens($userObj);
        $num = count($tokens);
        $max_num = $this->maxLoginNum($userObj) - 1;

        if ($num > $max_num) {
            usort($tokens, function ($prv, $next) {
                if ($prv[1] == $next) return 0;
                return $prv[1] > $next[1] ? 1 : -1;
            });
            $diff_num = $num - $max_num;
            $del_tokens = array_slice($tokens, 0, $diff_num);
            foreach ($del_tokens as $value) {
                $this->redis()->hDel($this->user_token_list, $value[0]);
            }
        }
    }

    private function getAllowRefreshToken(): bool
    {
        $allow = Context::get(AllowRefreshOrNotInterface::class, true);
        return $allow;
    }

    private function hashKey(AuthUserObj $userObj)
    {
        return $userObj->user_id . ':' . $userObj->guard . '_' . $userObj->str;
    }

    private function saveToken(AuthUserObj $userObj)
    {
        $this->redis()->hMSet($this->user_token_list, [
            $this->hashKey($userObj) => serialize($userObj)
        ]);
    }

    public function generate(string $guard, int $uid)
    {
        $userObj = new AuthUserObj($uid, $guard, $this->getTTL(), $this->getAllowRefreshToken());
        $token = $this->util->encryption(serialize($userObj));
        $this->delSurplusToken($userObj);
        go(fn() => $this->delExpireTokenFunc($userObj));
        $this->saveToken($userObj);
        return $token;
    }

    public function delete($token)
    {
        $userObj = $this->verify($token);
        $this->redis()->hDel($this->user_token_list, $this->hashKey($userObj));
    }

    public function refresh($token)
    {
        $userObj = $this->verify($token, true);
        if ($userObj->allow_refresh_token) {
            $now = Carbon::now();
            $expire = $userObj->expire_date;
            if ($now->diffInSeconds(Carbon::parse($expire)) > $this->config('allow_timeout_refresh', 30)) {
                $this->delete($token);
                $token = $this->generate($userObj->guard, $userObj->user_id);
                return $token;
            }
        }
        throw new TokenUnableToRefreshException('Token无法刷新！');
    }

    private function delExpireTokenFunc(AuthUserObj $userObj)
    {
        $now = Carbon::now()->getTimestamp();
        $it = null;

        $del = [];

        $search = $userObj->user_id . ':' . $userObj->guard . '*';

        while (true) {
            $arr = $this->redis()->hScan($this->user_token_list, $it, $search, 200);
            if ($arr === false) {
                break;
            }
            foreach ($arr as $key => $value) {
                $obj = unserialize($value);
                if (!$obj instanceof AuthUserObj) {
                    $del[] = $key;
                    continue;
                }
                if (Carbon::parse($obj->expire_date)->getTimestamp() < $now) {
                    $del[] = $key;
                }
            }
        }
        call_user_func_array([$this->redis(), 'hDel'], [$this->user_token_list, ...$del]);
    }

    public function verify($token, $local_verify = false): AuthUserObj
    {
        if (empty($token)) {
            throw new \Exception('无效的Token');
        }
        
        $userObj = unserialize($this->util->decrypt($token));

        if ($local_verify && is_object($userObj)){
            return $userObj;
        }

        if (is_object($userObj) && $userObj instanceof AuthUserObj) {
            if ($this->redis()->hGet($this->user_token_list, $this->hashKey($userObj))) {
                return $userObj;
            }
        }

        throw new \Exception('无效的Token');
    }
}
