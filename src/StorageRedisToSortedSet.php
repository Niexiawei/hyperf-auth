<?php


namespace Niexiawei\Auth;


use Carbon\Carbon;
use Hyperf\Contract\ConfigInterface;
use Hyperf\Di\Annotation\Inject;
use Hyperf\Redis\RedisFactory;
use Hyperf\Utils\Context;
use Hyperf\Utils\Str;
use Psr\Container\ContainerInterface;
use Swoole\Exception;

class StorageRedisToSortedSet implements StorageInterface
{
    /**
     * @Inject()
     * @var ConfigInterface
     */
    protected $configInterface;
    /**
     * @Inject()
     * @var RedisFactory
     */
    protected $RedisFactory;
    protected $user_token_list;

    public function __construct(ContainerInterface $container)
    {
        $this->user_token_list = env('APP_NAME','hyperf') . '_user_token_list';
    }

    /**
     * @param $key
     * @param string $default
     * @return mixed
     * 获取配置文件
     */

    public function config($key, $default = '')
    {
        return $this->configInterface->get('auth.' . $key, $default);
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

    /**
     * @param string $token
     * @return string
     * @throws Exception
     * 根据token获取集合中的key
     */

    private function tokenKey(string $token)
    {
        $origin = $this->unFormat($token);
        $key = $origin['guard'] . '_' . $origin['uid'] . '_' . $token . '_' . $origin['create_time'];
        return $key;
    }

    /**
     * @param string $token
     * @throws Exception
     * 保存 token
     */

    protected function tokenSave(string $token)
    {
        $this->delSurplusToken($token);
        $key = $this->tokenKey($token);
        $expire = $this->getTTL();
        $expire_timestamp = Carbon::now()->addSeconds($expire)->getTimestamp();
        $this->redis()->zAdd($this->user_token_list, [], $expire_timestamp, $key);
    }

    /**
     * @param string $token
     * @return int
     * @throws Exception
     * 检查token是否存在 存在返回 token 过期时间
     */

    public function tokenExists(string $token): int
    {
        $key = $this->tokenKey($token);
        $expire = $this->redis()->zScore($this->user_token_list, $key);
        if (empty($expire)) {
            return 0;
        }
        return $expire;
    }

    /**
     * @param string $token
     * @return array
     * @throws Exception
     * 获取 当前用户的 所有token
     */
    protected function getUidTokens(string $token)
    {
        $tokens = [];
        $now = Carbon::now()->getTimestamp();
        $origin = $this->unFormat($token);
        $search = $origin['guard'] . '_' . $origin['uid'] . '_*';
        $it = null;
        $del_expire_token = [];
        while (true) {
            $arr = $this->redis()->zScan($this->user_token_list, $it, $search);
            if ($arr === false) {
                break;
            }
            foreach ($arr as $token_key => $expire) {
                if ($now > $expire) {
                    $del_expire_token[] = $token_key;
                } else {
                    $tokens[] = ['token_key' => $token_key, 'expire' => $expire];
                }
            }
        }
        if (!empty($del_expire_token)) {
            $this->redis()->multi(\Redis::PIPELINE);
            foreach ($del_expire_token as $token) {
                $this->delToken($token);
            }
            $this->redis()->exec();
        }
        return $tokens;
    }

    /**
     * @param $token
     * 根据token_key 删除token
     */

    private function delToken($token)
    {
        $this->redis()->zRem($this->user_token_list, $token);
    }


    /**
     * @param string $guard
     * @param int $uid
     * @return string
     * @throws Exception
     * 生成 token
     */

    public function generate(string $guard, int $uid)
    {
        $data = [
            'guard' => $guard,
            'uid' => $uid,
            'create_time' => time(),
            'str' => Str::random(32),
            'allow_refresh_token' => $this->getAllowRefreshToken() ? 1 : 0
        ];
        $token = $this->format($data);
        $this->tokenSave($token);
        return $token;
    }

    /**
     * @param array $data
     * @return string
     * 格式化 token
     */

    private function format(array $data)
    {
        $key = $this->config('key');
        $token_head = base64_encode(json_encode($data));
        $token_sign = md5($token_head . $key);
        return $token_head . '.' . $token_sign;
    }


    /**
     * @param string $token
     * @return array|mixed
     * @throws Exception
     * 解析token
     */

    private function unFormat(string $token)
    {
        $origin = $this->tokenToOrigin($token);
        if (!empty($origin)) {
            return $origin;
        } else {
            $origin = explode('.', $token);
            if (isset($origin[0]) && isset($origin[1])) {
                $token_head = $origin[0];
                $token_sign = $origin[1];
                $origin_token = json_decode(base64_decode($token_head), true);
                $origin_token['sign'] = $token_sign;
                $this->tokenToOriginCache($token, $origin_token);
                return $origin_token;
            }
        }
        throw new Exception('Token无法解析');
    }

    /**
     * @return bool
     * 获取 token 是否可以 刷新
     */

    private function getAllowRefreshToken(): bool
    {
        $allow = Context::get(AllowRefreshOrNotInterface::class, true);
        return $allow;
    }

    /**
     * @param $token
     * @throws Exception
     * 删除token  退出登录用
     */

    public function delete($token)
    {
        $keys = $this->tokenKey($token);
        $this->redis()->zRem($this->user_token_list, $keys);
    }

    /**
     * @return mixed|setTokenExpireInterface|null
     * 获取 token过期时间
     */

    private function getTTL()
    {
        $config = $this->config('expire', 3600 * 24);
        $second = Context::get(setTokenExpireInterface::class, $config);
        return $second;
    }

    /**
     * @param $token
     * @throws Exception
     * 删除 超出最大登录的token
     */

    private function delSurplusToken($token)
    {
        $tokens = $this->getUidTokens($token);
        $num = count($tokens);
        $max_num = $this->config('max_login_num', 7) - 1;
        if ($num > $max_num) {
            $delNum = $num - $max_num;
            array_multisort(array_column($tokens, 'expire'), SORT_ASC, $tokens);
            $delTokens = array_splice($tokens, 0, $delNum);
            $del_token_arr = array_map(function ($tokens) {
                return $tokens['token_key'];
            }, $delTokens);
            if (!empty($del_token_arr)) {
                $this->redis()->multi(\Redis::PIPELINE);
                foreach ($del_token_arr as $token) {
                    $this->delToken($token);
                }
                $this->redis()->exec();
            }
        }
    }


    /**
     * @param $token
     * @throws Exception
     * 刷新token
     */
    public function refresh($token)
    {
        $origin = $this->unFormat($token);
        $expire_timestamp = $this->tokenExists($token);
        $token_key = $this->tokenKey($token);
        $create_time = Carbon::createFromTimestamp($origin['create_time']);
        $expire_time = Carbon::createFromTimestamp($expire_timestamp);
        $max_login_time = $this->config('max_login_time', 3600 * 24);
        if ($create_time->diffInSeconds($create_time) <= $max_login_time) {
            $expire = $expire_time->addSeconds($this->getTTL())->getTimestamp();
            $this->redis()->zAdd($this->user_token_list, [], $expire, $token_key);
        }
    }

    /**
     * @param $token
     * @return array
     * @throws Exception
     * 验证token
     */

    public function verify($token): array
    {
        $this->getUidTokens($token);
        $expire = $this->tokenExists($token);
        if ($expire <= 0 || Carbon::now()->getTimestamp() > $expire) {
            return [];
        }
        $this->refresh($token);
        return $this->unFormat($token);
    }

    /**
     * @param $token
     * @return array|mixed
     * @throws Exception
     * 格式化token
     */

    public function formatToken($token)
    {
        return $this->unFormat($token);
    }

    /**
     * @param $token
     * @param $orgin
     * 缓存
     */

    private function tokenToOriginCache($token, $orgin)
    {
        $token_cache = Context::get('tokens_cache', []);
        Context::set('tokens_cache', array_merge($token_cache, [$token => $orgin]));
    }

    /**
     * @param $token
     * @return array
     * 获取缓存
     */

    private function tokenToOrigin($token)
    {
        $token_cache = Context::get('tokens_cache', []);
        return $token_cache[$token] ?? [];
    }
}
