<?php


namespace Niexiawei\Auth;


use Carbon\Carbon;
use Hyperf\Contract\ConfigInterface;
use Hyperf\Utils\Context;
use Hyperf\Utils\Str;
use Niexiawei\Auth\Event\TokenCreate;
use Niexiawei\Auth\Event\TokenRefresh;
use Psr\Container\ContainerInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use function Sodium\add;

class StorageRedis
{
    private $config;
    private $expire;
    private $refresh_expire;
    private $key;
    private $max_login_num;
    private $surplus;
    private $renewal;
    private $storage_prefix;
    private $redis;
    protected $event;

    public function __construct(ContainerInterface $container)
    {
        $this->config = $config = $container->get(ConfigInterface::class);
        $this->expire = $config->get('auth.expire', 3600 * 24);
        $this->refresh_expire = $config->get('auth.refresh_expire', 3600 * 24 * 30);
        $this->key = $config->get('auth.key');
        $this->max_login_num = $config->get('auth.max_login_num', 7);
        $this->surplus = $config->get('auth.surplus', 60 * 2);
        $this->renewal = $config->get('auth.renewal', 3600 * 12);
        $this->storage_prefix = $config->get('auth.storage_prefix', 'user_token');
        $this->redis = $container->get(\Redis::class);
        $this->event = $container->get(EventDispatcherInterface::class);
    }

    private function storageToken($token)
    {
        $key = $this->getTokenKey($token);
        $raw_token = $this->redis->get($key);
        if (empty($raw_token)) {
            return [$key,''];
        }
        $raw_token = json_decode($raw_token, true);
        return [$key,$raw_token];
    }

    public function refresh($token)
    {
        $time = time();
        [$tokenKey,$token_info] = $this->storageToken($token);
        if($token_info['refresh_expire'] >$time){
            if($token_info['expire'] - $time < $this->surplus){
                $ttl = $this->redis->ttl($tokenKey);
                $renewal = $ttl + $this->renewal;
                $this->redis->expire($tokenKey,$renewal);
                $this->event->dispatch(new TokenRefresh($token,$renewal));
            }
        }
    }

    public function delete($token)
    {
        $key = $this->getTokenKey($token);
        $this->redis->del($key);
    }

    public function verify($token): array
    {
        [$key,$raw_token] = $this->storageToken($token);
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

    public function formatToken($token)
    {
        $token = explode('.', $token);
        $raw_data = json_decode(base64_decode($token[0]), true);
        $sign = $token[1] ?? '';
        $raw_data['sign'] = $sign;
        return $raw_data;
    }


    private function tokenNum($guard, $uid)
    {
        $it = null;
        $keys = $this->userPrefix($guard, $uid);
        $num = 0;
        $tokens = [];
        while ($arr = $this->redis->scan($it, $keys . '*', $this->max_login_num + 1)) {
            foreach ($arr as $key => $value) {
                $tokens[$key] = $value;
                $num++;
            }
        }
        return [$num, $tokens];
    }

    private function delSurplusToken($guard, $uid)
    {
        [$num, $tokens] = $this->tokenNum($guard, $uid);
        if ($num >= $this->max_login_num) {
            $token_list = array_values($tokens);
            $index = random_int(0, $num - 1);
            if(!isset($token_list[$index])){
                $key = $token_list[$index - 1];
            }else{
                $key = $token_list[$index];
            }
            $this->redis->del($key);
        }

    }


    public function generate(string $guard, int $uid)
    {
        $this->delSurplusToken($guard, $uid);
        $raw_user_data = [
            'guard' => $guard,
            'uid' => $uid,
            'create_time' => Carbon::now()->getTimestamp(),
            'expire' => Carbon::now()->addSeconds($this->expire)->getTimestamp(),
            'random' => Str::random(20),
            'refresh_expire' => Carbon::now()->addSeconds($this->refresh_expire)->getTimestamp(),
        ];
        $token_start = base64_encode(json_encode($raw_user_data));
        $token_sign = $this->tokenSign($token_start);
        $token = $token_start . '.' . $token_sign;
        $this->save($raw_user_data, $token);
        $this->event->dispatch(new TokenCreate($token, $uid, $guard));
        return $token;
    }

    private function save($raw_user_data, $token)
    {
        $raw_user_data['token'] = $token;
        $this->redis->setex($this->getTokenKey($token), $this->expire, json_encode($raw_user_data));
    }

    private function tokenSign($origin_token)
    {
        return md5($origin_token . $this->key);
    }

    private function getTokenKey($token)
    {
        $token_info = $this->formatToken($token);
        $guard = $token_info['guard'] ?? '';
        $uid = $token_info['uid'] ?? '';
        $sign = $token_info['sign'] ?? 0;
        return $this->storage_prefix . $guard . $uid . '_' .$sign;
    }

    private function userPrefix($guard, $uid)
    {
        return $this->storage_prefix . $guard . $uid . '_';
    }

}
