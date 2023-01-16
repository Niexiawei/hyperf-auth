<?php

namespace Niexiawei\Auth\Driver;


use Carbon\Carbon;
use Hyperf\Contract\ConfigInterface;
use Hyperf\Contract\StdoutLoggerInterface;
use Hyperf\Crontab\Annotation\Crontab;
use Hyperf\Di\Annotation\Inject;
use Hyperf\Redis\RedisFactory;
use Hyperf\Context\Context;
use Hyperf\Redis\RedisProxy;
use Niexiawei\Auth\AuthUserObj;
use Niexiawei\Auth\Constants\AllowRefreshOrNotInterface;
use Niexiawei\Auth\Constants\setTokenExpireInterface;
use Niexiawei\Auth\DriverInterface;
use Niexiawei\Auth\Exception\NoTokenPassedInException;
use Niexiawei\Auth\Exception\TokenGenerateErrorException;
use Niexiawei\Auth\Exception\TokenInvalidException;
use Niexiawei\Auth\Exception\TokenUnableToRefreshException;
use Niexiawei\Auth\Util;

class RedisDriver implements DriverInterface
{
    public string $user_token_list = 'user_token_list';

    #[Inject]
    protected RedisFactory $RedisFactory;

    #[Inject]
    protected ConfigInterface $config;

    #[Inject]
    protected StdoutLoggerInterface $stdoutLogger;

    /**
     * @throws TokenInvalidException
     * @throws TokenUnableToRefreshException
     * @throws NoTokenPassedInException
     */
    public function refresh($token): string
    {
        $userObj = $this->verify($token, true);
        if ($userObj->allow_refresh_token) {
            $now = Carbon::now()->getTimestamp();
            $expire = Carbon::parse($userObj->expire_date)->getTimestamp();
            $diff_second = $now - $expire;
            if ($expire > $now || $diff_second <= $this->config('allow_timeout_refresh', 30)) {
                $this->delete($token);
                return $this->generate($userObj->guard, $userObj->user_id);
            }
        }
        throw new TokenUnableToRefreshException('Token无法刷新!');
    }

    /**
     * @throws TokenInvalidException
     * @throws NoTokenPassedInException
     */
    public function verify($token, $local_verify = false): AuthUserObj
    {
        if (empty($token)) {
            throw new NoTokenPassedInException('Token不能为空');
        }

        $userObj = unserialize(Util::decrypt($token));

        if ($local_verify && $userObj instanceof AuthUserObj) {
            return $userObj;
        }

        /**
         * @var $tokens AuthUserObj[]
         */

        if ($userObj instanceof AuthUserObj && isset($userObj->id)) {
            $tokens = $this->getUidTokens($userObj);
            if (empty($tokens)) {
                throw new TokenInvalidException('无效的Token');
            }

            if (!in_array($userObj->id, array_keys($tokens))) {
                throw new TokenInvalidException('无效的Token');
            }

            if (Carbon::parse($tokens[$userObj->id]->expire_date)->getTimestamp() <= Carbon::now()->getTimestamp()) {
                throw new TokenInvalidException('Token已失效,请重新登录!');
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
     * @return RedisProxy
     * 获取Redis
     */

    protected function redis(): RedisProxy
    {
        $pool = $this->config('redis_pool', 'default');
        return $this->RedisFactory->get($pool);
    }

    public function config($key, $default = '')
    {
        return $this->config->get('auth.' . $key, $default);
    }

    private function hashKey(AuthUserObj $userObj): string
    {
        return $userObj->user_id . ':' . $userObj->guard;
    }

    public function delete($token): array
    {
        $userObj = $this->verify($token, true);
        $tokens = $this->getUidTokens($userObj);

        /**
         * @var $tokens AuthUserObj[]
         */

        foreach ($tokens as $id => $token) {
            if ($token->id == $userObj->id) {
                unset($tokens[$id]);
            }
        }
        try {
            $this->redis()->hSet($this->user_token_list, $this->hashKey($userObj), serialize($tokens));
        } catch (\RedisException $e) {
        }

        return $tokens;
    }

    public function generate(string $guard, int $uid): string
    {
        $userObj = new AuthUserObj($uid, $guard, $this->getTTL(), $this->getAllowRefreshToken());
        $tokens = $this->getUidTokens($userObj);
        $login_token_num = count($tokens);
        $max_token_num = $this->maxLoginNum($userObj);

        if ($login_token_num >= $max_token_num) {
            $this->delSurplusToken($userObj, $tokens, ($login_token_num - $max_token_num) + 1);
        }

        $token = Util::encryption(serialize($userObj));
        $this->saveToken($userObj);
        $this->delExpireToken($userObj, [$userObj->id]);
        return $token;
    }

    private function getTTL(): int
    {
        $config = $this->config('expire', 3600 * 24);
        return Context::get(setTokenExpireInterface::class, $config);
    }

    private function getAllowRefreshToken(): bool
    {
        return Context::get(AllowRefreshOrNotInterface::class, true);
    }

    private function maxLoginNum(AuthUserObj $userObj): int
    {
        $config = $this->config('guards.' . $userObj->guard);
        if (isset($config['max_login_num'])) {
            return $config['max_login_num'];
        }

        return $this->config('max_login_num', 7);
    }

    public function delSurplusToken(AuthUserObj $userObj, array $tokens, $delete_nums = 1): void
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

        try {
            $this->redis()->hSet($this->user_token_list, $this->hashKey($userObj), serialize($tokens));
        } catch (\RedisException $e) {
        }
    }

    /**
     * @throws TokenGenerateErrorException
     */
    private function saveToken(AuthUserObj $userObj): void
    {
        try {
            $tokens = $this->redis()->hGet($this->user_token_list, $this->hashKey($userObj));
        } catch (\RedisException $e) {
            throw new TokenGenerateErrorException();
        }

        if ($tokens === false) {
            $tokens = [];
        } else {
            $tokens = unserialize($tokens);
        }

        $tokens[$userObj->id] = $userObj;
        try {
            $this->redis()->hSet($this->user_token_list, $this->hashKey($userObj), serialize($tokens));
        } catch (\RedisException $e) {
            throw new TokenGenerateErrorException();
        }
    }

    private function delExpireToken(AuthUserObj $userObj, array $ignore_token_id_list = [])
    {
        $now = Carbon::now()->getTimestamp();

        $tokens = $this->getUidTokens($userObj);

        /**
         * @var $tokens AuthUserObj[]
         */

        $ignore_token_id_list_empty = false;

        if (empty($ignore_token_id_list)) {
            $ignore_token_id_list_empty = true;
        }

        foreach ($tokens as $id => $token) {
            if (!$ignore_token_id_list_empty && in_array($id, $ignore_token_id_list)) {
                continue;
            }

            if (Carbon::parse($token->expire_date)->getTimestamp() < $now) {
                unset($tokens[$id]);
            }
        }

        try {
            $this->redis()->hSet($this->user_token_list, $this->hashKey($userObj), serialize($tokens));
        } catch (\RedisException $e) {
        }
    }

    /**
     * 清理过期token 定时任务
     */
    #[Crontab(name: 'AuthRedisDriveDeleteExpireTokens', rule: '10 */2 * * *', onOneServer: true, singleton: true)]
    public function deleteExpireTokens()
    {
        /**
         * @var $userObjList AuthUserObj[]
         */

        try {
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
                        /** @var $item AuthUserObj */
                        if (Carbon::parse($item->expire_date)->getTimestamp() <= $now_timestamp) {
                            unset($userObjList[$id]);
                        }
                    }

                    $this->redis()->hSet($this->user_token_list, $hash_key, serialize($userObjList));
                }
            }
        } catch (\Throwable $exception) {
            $this->stdoutLogger->error("AuthRedisDriveDeleteExpireTokens任务执行失败");
            $this->stdoutLogger->error($exception->getMessage());
            $this->stdoutLogger->error($exception->getTraceAsString());
        }
    }
}
