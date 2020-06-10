<?php

namespace Niexiawei\Auth\Drive;


use Carbon\Carbon;
use Hyperf\Contract\ConfigInterface;
use Hyperf\Di\Annotation\Inject;
use Hyperf\Redis\RedisFactory;
use Hyperf\Utils\Context;
use Niexiawei\Auth\AllowRefreshOrNotInterface;
use Niexiawei\Auth\AuthUserObj;
use Niexiawei\Auth\DriveInterface;
use Niexiawei\Auth\setTokenExpireInterface;
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

    private function getTTL()
    {
        $config = $this->config('expire', 3600 * 24);
        $second = Context::get(setTokenExpireInterface::class, $config);
        return $second;
    }

    public function getUidTokens(string $token)
    {
        $userObj = $this->verify($token);
        $tokens = [];
        $now = Carbon::now();
        $search = $userObj->user_id . '_*';
        $it = null;
        $del_expire_token = [];
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

    public function delSurplusToken($token)
    {
        $tokens = $this->getUidTokens($token);
        $num = count($tokens);
        $max_num = $this->config('max_login_num', 7) - 1;
        if ($num > $max_num) {
            usort($tokens, function ($prv, $next) {
                if ($prv[1] == $next) return 0;
                return $prv[1] > $next[1] ? 1 : -1;
            });
            $diff_num = $num - $max_num;
            $del_tokens = array_slice($tokens, 0, $diff_num);
            $this->redis()->multi(\Redis::PIPELINE);
            foreach ($del_tokens as $value) {
                $this->redis()->hDel($this->user_token_list, $value[0]);
            }
            $this->redis()->exec();
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
        $this->redis()->hMSet($this->user_token_list, [
            $this->hashKey($userObj) => serialize($userObj)
        ]);
    }

    public function generate(string $guard, int $uid)
    {
        $userObj = new AuthUserObj($uid, $guard, $this->getTTL(), $this->getAllowRefreshToken());
        $token = $this->util->encryption(serialize($userObj));
        $this->saveToken($userObj);
        $this->delSurplusToken($token);
        $this->delExpireToken($token);
        return $token;
    }

    public function delete($token)
    {
        $userObj = $this->verify($token);
        $this->redis()->hDel($this->user_token_list, $this->hashKey($userObj));
    }

    public function refresh(AuthUserObj $userObj)
    {
        if ($userObj->allow_refresh_token) {
            if (Carbon::parse($userObj->expire_date)->diffInSeconds(Carbon::now()) < 3600) {
                $userObj->refresh(3600);
                $this->saveToken($userObj);
            }
        }
    }

    private function delExpireToken($token)
    {
        $tokens = $this->getUidTokens($token);
        $now = Carbon::now()->getTimestamp();
        $this->redis()->multi(\Redis::PIPELINE);
        foreach ($tokens as $value) {
            if ($value[1] < $now) {
                $this->redis()->hDel($this->user_token_list, $value[0]);
            }
        }
        $this->redis()->exec();
    }

    public function verify($token): AuthUserObj
    {
        $userObj = unserialize($this->util->decrypt($token));
        if ($userObj instanceof AuthUserObj) {
            $hash_key = $this->hashKey($userObj);
            $cacheUserObj = $this->getCache($hash_key);
            if (!empty($cacheUserObj) && $cacheUserObj instanceof AuthUserObj) {
                return $cacheUserObj;
            }

            $locaUserObj = $this->redis()->hGet($this->user_token_list, $hash_key);
            if (!empty($locaUserObj)) {
                $locaUserObj = unserialize($locaUserObj);
                if ($locaUserObj instanceof AuthUserObj) {
                    if (Carbon::parse($locaUserObj->expire_date) > Carbon::now()) {
                        $this->setCache($hash_key, $userObj);
                        $this->refresh($userObj);
                        return $locaUserObj;
                    }
                }
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
