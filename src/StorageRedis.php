<?php


namespace Niexiawei\Auth;


use Carbon\Carbon;
use Hyperf\Contract\ConfigInterface;
use Hyperf\Redis\RedisFactory;
use Hyperf\Utils\Context;
use Hyperf\Utils\Str;
use Psr\Container\ContainerInterface;

class StorageRedis implements StorageInterface
{
    protected $config;
    protected $expire;
    protected $key;
    protected $max_login_num;
    protected $storage_prefix;
    protected $redis;
    protected $max_login_time;

    public function __construct(ContainerInterface $container)
    {
        $this->config = $config = $container->get(ConfigInterface::class);
        $this->key = $config->get('auth.key');
        $this->max_login_num = $config->get('auth.max_login_num', 7);
        $this->storage_prefix = $config->get('auth.storage_prefix', 'user_token');
        $this->redis = $this->redis($container);
        $this->max_login_time = $config->get('auth.max_login_time', 3600 * 24 * 30);
    }

    protected function redis(ContainerInterface $container){
        $redis = $container->get(RedisFactory::class)->get('default');
        $redis->setOption(\Redis::OPT_SCAN,\Redis::SCAN_RETRY);
        return $redis;
    }


    private function getAllowRefreshToken(): bool
    {
        $allow = Context::get(AllowRefreshOrNotInterface::class,true);
        return  $allow;
    }

    private function getTTL()
    {
        $config = $this->config->get('auth.expire', 3600 * 24);
        $second = Context::get(setTokenExpireInterface::class,$config);
        return $second;
    }

    public function verify($token): array
    {
        [$key, $raw_token] = $this->storageToken($token);
        if (empty($raw_token)) {
            return [];
        }
        if ($token !== $raw_token['token']) {
            return [];
        }
        if (Carbon::now()->getTimestamp() > $raw_token['expire']) {
            $this->delete($token);
            return [];
        }
        $this->refresh($token);
        return $raw_token;
    }

    private function storageToken($token)
    {
        $key = $this->getTokenKey($token);
        $raw_token = $this->redis->get($key);
        if (empty($raw_token)) {
            throw new \Exception('token不存在');
        }
        $raw_token = json_decode($raw_token, true);
        return [$key, $raw_token];
    }

    private function getTokenKey($token)
    {
        $token_info = $this->formatToken($token);
        $guard = $token_info['guard'] ?? '';
        $uid = $token_info['uid'] ?? '';
        $sign = $token_info['sign'] ?? 0;
        return $this->storage_prefix . $guard . $uid . '_' . $sign.'_'.time();
    }

    public function formatToken($token)
    {
        $raw_data = [];
        $token = explode('.', $token);
        if (isset($token[0]) && isset($token[1])) {
            $raw_data = json_decode(base64_decode($token[0]), true);
            if (empty($raw_data)) {
                $raw_data = [];
            }
            $sign = $token[1] ?? '';
            $raw_data['sign'] = $sign;
            return $raw_data;
        }
        throw new \Exception('token格式错误，无法解析');
    }

    public function delete($token)
    {
        $key = $this->getTokenKey($token);
        $this->redis->del($key);
    }

    public function refresh($token)
    {
        $time = time();
        [$key, $token] = $this->storageToken($token);
        if (isset($token['allow_refresh_token']) && $token['allow_refresh_token'] == 1) {
            if ($time < $token['expire']) {
                $ttl = $this->redis->ttl($key);
                if ($ttl < 3600) {
                    $this->redis->expire($key, $ttl + 3600);
                }
            }
        }
    }

    public function generate(string $guard, int $uid)
    {
        $raw_user_data = [
            'guard' => $guard,
            'uid' => $uid,
            'create_time' => Carbon::now()->getTimestamp(),
            'expire' => Carbon::now()->addSeconds($this->max_login_time)->getTimestamp(),
            'random' => Str::random(32),
            'allow_refresh_token' => $this->getAllowRefreshToken() ? 1 : 0
        ];
        $token_start = base64_encode(json_encode($raw_user_data));
        $token_sign = $this->tokenSign($token_start);
        $token = $token_start . '.' . $token_sign;
        $this->save($raw_user_data, $token);
        $this->delSurplusToken($guard, $uid);
        return $token;
    }

    private function delSurplusToken($guard, $uid)
    {
        $token_list = [];
        $max_login = $this->max_login_num;
        [$num, $tokens] = $this->tokenNum($guard, $uid);
        if ($num > $max_login) {
            $delNum = $num - $max_login;
            foreach ($tokens as $token){
                $format = explode('_',$token);
                $token_list[array_pop($format)] = $token;
            }
            ksort($token_list);
            var_dump($token_list);
            $this->redis->del(array_slice($token_list,0,$delNum));
        }
    }

    private function tokenNum($guard, $uid)
    {
        $it = null;
        $keys = $this->userPrefix($guard, $uid);
        $num = 0;
        $tokens = [];
        while ($arr = $this->redis->scan($it, $keys . '*', 20)) {
            foreach ($arr as $key => $value) {
                $tokens[] = $value;
            }
        }
        $num = count($tokens);
        return [$num, $tokens];
    }

    private function userPrefix($guard, $uid)
    {
        return $this->storage_prefix . $guard . $uid . '_';
    }

    private function tokenSign($origin_token)
    {
        return md5($origin_token . $this->key);
    }

    private function save($raw_user_data, $token)
    {
        $raw_user_data['token'] = $token;
        $this->redis->setex($this->getTokenKey($token), $this->getTTL(), json_encode($raw_user_data));
    }

}
