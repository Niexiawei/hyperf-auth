<?php

namespace Niexiawei\Auth\Drive;


use Carbon\Carbon;
use Hyperf\Contract\ConfigInterface;
use Hyperf\Crontab\Annotation\Crontab;
use Hyperf\Di\Annotation\Inject;
use Hyperf\Redis\RedisFactory;
use Hyperf\Utils\Context;
use Niexiawei\Auth\AuthUserObj;
use Niexiawei\Auth\Constants\AllowRefreshOrNotInterface;
use Niexiawei\Auth\Constants\setTokenExpireInterface;
use Niexiawei\Auth\DriveInterface;
use Niexiawei\Auth\Exception\NoTokenPassedInException;
use Niexiawei\Auth\Exception\TokenInvalidException;
use Niexiawei\Auth\Exception\TokenUnableToRefreshException;
use Niexiawei\Auth\Util;

class RedisDrive implements DriveInterface
{
    public $user_token_list = 'user_token_list';
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
        throw new TokenUnableToRefreshException('Token无法刷新!');
    }

    public function verify($token, $local_verify = false): AuthUserObj
    {
        if (empty($token)) {
            throw new NoTokenPassedInException('Token不能为空');
        }

        $userObj = unserialize($this->util->decrypt($token));

        if ($local_verify && is_object($userObj)) {
            return $userObj;
        }

        /**
         * @var $tokens AuthUserObj[]
         */

        if (is_object($userObj) && $userObj instanceof AuthUserObj) {
            $tokens = $this->getUidTokens($userObj);

            if (empty($tokens)) {
                throw new TokenInvalidException('无效的Token');
            }

            if (!in_array($userObj->id, array_keys($tokens))) {
                throw new TokenInvalidException('无效的Token');
            }

            if (Carbon::parse($tokens[$userObj->id]->expire_date)->getTimestamp() <= Carbon::now()->getTimestamp()) {
                throw new TokenInvalidException('无效的Token');
            }

            return $userObj;
        }

        throw new TokenInvalidException('无效的Token');
    }

    public function getUidTokens(AuthUserObj $userObj): array
    {
        $tokens = $this->redis()->hGet($this->user_token_list, $this->hashKey($userObj));
        if ($tokens === false) {
            return [];
        }
        return unserialize($tokens);
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

    public function config($key, $default = '')
    {
        return $this->config->get('auth.' . $key, $default);
    }

    private function hashKey(AuthUserObj $userObj)
    {
        return $userObj->user_id . ':' . $userObj->guard;
    }

    public function delete($token)
    {
        $userObj = $this->verify($token);
        $tokens = $this->getUidTokens($userObj);

        /**
         * @var $tokens AuthUserObj[]
         */

        foreach ($tokens as $id => $token) {
            if ($token->id == $userObj->id) {
                unset($tokens[$id]);
            }
        }
        $this->redis()->hSet($this->user_token_list, $this->hashKey($userObj), serialize($tokens));

        return $tokens;
    }

    public function generate(string $guard, int $uid)
    {
        $userObj = new AuthUserObj($uid, $guard, $this->getTTL(), $this->getAllowRefreshToken());
        $tokens = $this->getUidTokens($userObj);
        $login_token_num = count($tokens);
        $max_token_num = $this->maxLoginNum($userObj);

        if ($login_token_num >= $max_token_num) {
            $this->delSurplusToken($userObj, $tokens, ($login_token_num - $max_token_num) + 1);
        }

        $token = $this->util->encryption(serialize($userObj));
        go(fn() => $this->delExpireToken($userObj));
        $this->saveToken($userObj);
        return $token;
    }

    private function getTTL()
    {
        $config = $this->config('expire', 3600 * 24);
        $second = Context::get(setTokenExpireInterface::class, $config);
        return $second;
    }

    private function getAllowRefreshToken(): bool
    {
        $allow = Context::get(AllowRefreshOrNotInterface::class, true);
        return $allow;
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

    public function delSurplusToken(AuthUserObj $userObj, array $tokens, $delete_nums = 1)
    {
        /**
         * @var $tokens AuthUserObj[]
         */

        $nums = $delete_nums;

        asort($tokens);
        foreach ($tokens as $id => $token) {
            if ($nums <= 0) {
                break;
            }
            unset($tokens[$id]);
            $nums--;
        }

        $this->redis()->hSet($this->user_token_list, $this->hashKey($userObj), serialize($tokens));

    }

    private function delExpireToken(AuthUserObj $userObj)
    {
        $now = Carbon::now()->getTimestamp();
        $it = null;

        $del = [];

        $tokens = $this->getUidTokens($userObj);

        /**
         * @var $tokens AuthUserObj[]
         */

        foreach ($tokens as $id => $token) {
            if (Carbon::parse($token->expire_date)->getTimestamp() < $now) {
                unset($tokens[$id]);
            }
        }

        $this->redis()->hSet($this->user_token_list, $this->hashKey($userObj), serialize($tokens));
//        while (true) {
//            $arr = $this->redis()->hScan($this->user_token_list, $it, $search, 200);
//            if ($arr === false) {
//                break;
//            }
//            foreach ($arr as $key => $value) {
//                $obj = unserialize($value);
//                if (!$obj instanceof AuthUserObj) {
//                    $del[] = $key;
//                    continue;
//                }
//                if (Carbon::parse($obj->expire_date)->getTimestamp() < $now) {
//                    $del[] = $key;
//                }
//            }
//        }
//        call_user_func_array([$this->redis(), 'hDel'], [$this->user_token_list, ...$del]);
    }

    private function saveToken(AuthUserObj $userObj)
    {
        $tokens = $this->redis()->hGet($this->user_token_list, $this->hashKey($userObj));

        if ($tokens === false) {
            $tokens = [];
            $tokens[$userObj->id] = $userObj;
        } else {
            $tokens = unserialize($tokens);
            $tokens[$userObj->id] = $userObj;
        }

        $this->redis()->hSet($this->user_token_list, $this->hashKey($userObj), serialize($tokens));
    }

    /**
     * 清理过期token 定时任务
     */
    #[Crontab(name: 'AuthRedisDriveDeleteExpireTokens', rule: '10 */2 * * *', onOneServer: true, singleton: true)]
    public function deleteExpireToken()
    {
        /**
         * @var $token AuthUserObj[]
         */

        $now_timestamp = Carbon::now()->getTimestamp();

        $it = null;
        while (true) {
            $tokens = $this->redis()->hScan($this->user_token_list, $it, '*', 50);
            if ($tokens === false) {
                break;
            }
            foreach ($tokens as $hash_key => $token) {
                $userObjList = unserialize($token);
                if (empty($userObjList) || count($userObjList) <= 0) {
                    continue;
                }

                foreach ($userObjList as $id => $item) {
                    if (Carbon::parse($item->expire_date)->getTimestamp() <= $now_timestamp) {
                        unset($userObjList[$id]);
                    }
                }

                $this->redis()->hSet($this->user_token_list, $hash_key, serialize($userObjList));
            }
        }
    }
}
