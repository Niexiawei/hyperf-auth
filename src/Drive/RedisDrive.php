<?php

namespace Niexiawei\Auth\Drive;


use Carbon\Carbon;
use Hyperf\Contract\ConfigInterface;
use Hyperf\Di\Annotation\Inject;
use Hyperf\Redis\RedisFactory;
use Hyperf\Utils\ApplicationContext;
use Hyperf\Utils\Context;
use Niexiawei\Auth\AllowRefreshOrNotInterface;
use Niexiawei\Auth\AuthUserObj;
use Niexiawei\Auth\DriveInterface;
use Niexiawei\Auth\Exception\TokenUnableToRefreshException;
use Niexiawei\Auth\setTokenExpireInterface;
use Niexiawei\Auth\SwooleTableIncr;
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

    private function getUserTokenList(AuthUserObj $userObj)
    {
        return $this->user_token_list . $userObj->guard;
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
        $search = $userObj->user_id . '_*';
        $it = null;
        while (true) {
            $arr = $this->redis()->hScan($this->getUserTokenList($userObj), $it, $search);
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
        $userTokenList = $this->getUserTokenList($userObj);
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
                $this->redis()->hDel($userTokenList, $value[0]);
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
        return $userObj->user_id . '_' . $userObj->str;
    }

    private function saveToken(AuthUserObj $userObj)
    {
        $this->redis()->hMSet($this->getUserTokenList($userObj), [
            $this->hashKey($userObj) => serialize($userObj)
        ]);
    }

    public function generate(string $guard, int $uid)
    {
        $userObj = new AuthUserObj($uid, $guard, $this->getTTL(), $this->getAllowRefreshToken());
        $token = $this->util->encryption(serialize($userObj));
        $this->delSurplusToken($userObj);
        $this->delExpireToken($userObj);
        $this->saveToken($userObj);
        return $token;
    }

    public function delete($token)
    {
        $userObj = $this->verify($token);
        $this->redis()->hDel($this->getUserTokenList($userObj), $this->hashKey($userObj));
    }


    public function refresh($token)
    {
        $userObj = $this->verify($token, false);
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


    private function incr(): SwooleTableIncr
    {
        return ApplicationContext::getContainer()->get(SwooleTableIncr::class);
    }

    private function delExpireToken(AuthUserObj $userObj)
    {
        if ($this->incr()->getNum() >= 200) {
            $this->delExpireTokenFunc($userObj);
            $this->incr()->initNum();
        } else {
            $this->incr()->addIncr();
        }
    }

    private function delExpireTokenFunc(AuthUserObj $userObj)
    {
        $userTokenList = $this->getUserTokenList($userObj);
        $now = Carbon::now()->getTimestamp();
        $it = null;
        while (true) {
            $arr = $this->redis()->hScan($userTokenList, $it, '*', 200);
            if ($arr === false) {
                break;
            }
            foreach ($arr as $key => $value) {
                if ($value instanceof AuthUserObj) {
                    if (Carbon::parse($value->expire_date)->getTimestamp() < $now) {
                        $this->redis()->hDel($userTokenList, $key);
                    }
                }
            }
        }
    }

    public function verify($token, $local_verify = true): AuthUserObj
    {
        if (empty($token)){
            throw new \Exception('无效的Token');
        }
        $userObj = unserialize($this->util->decrypt($token));
        if ($userObj instanceof AuthUserObj) {
            $userTokenList = $this->getUserTokenList($userObj);
            $hash_key = $this->hashKey($userObj);
            $cacheUserObj = $this->getCache($hash_key);
            if (!empty($cacheUserObj) && $cacheUserObj instanceof AuthUserObj) {
                return $cacheUserObj;
            }
            if ($local_verify) {
                $locaUserObj = $this->redis()->hGet($userTokenList, $hash_key);
                if (!empty($locaUserObj)) {
                    $locaUserObj = unserialize($locaUserObj);
                    if ($locaUserObj instanceof AuthUserObj) {
                        if (Carbon::parse($locaUserObj->expire_date) > Carbon::now()) {
                            $this->setCache($hash_key, $userObj);
                            return $locaUserObj;
                        }
                    }
                }
            } else {
                return $userObj;
            }
        }
        throw new \Exception('无效的Token');
    }

    private function setCache($key, $value)
    {
        Context::set($key, $value);
    }

    private function getCache($key)
    {
        return Context::get($key);
    }

}
