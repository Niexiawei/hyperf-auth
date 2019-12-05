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
    private $hash_list_key;
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
        $this->hash_list_key = $config->get('auth.hash_list_key', 'user_token');
        $this->redis = $container->get(\Redis::class);
        $this->event = $container->get(EventDispatcherInterface::class);
    }

    private function getTokenInfo($token)
    {
        [$hashKey,$hashListKey,$raw] = $this->tokenAnalysis($token);
        $raw_token = $this->redis->hGet($hashListKey,$hashKey);
        if (empty($raw_token)) {
            return [];
        }
        return json_decode($raw_token, true);
    }

    public function refresh($token)
    {
        [$hashKey,$hashListKey,$raw] = $this->tokenAnalysis($token);
        if ($raw['refresh_expire'] > Carbon::now()->getTimestamp()) {
            if ($raw['expire'] - Carbon::now()->getTimestamp() < $this->surplus) {
                $raw['expire'] = Carbon::now()->addSeconds($this->renewal)->getTimestamp();
                $this->redis->hSet($hashListKey, $hashKey, json_encode($raw));
                $this->event->dispatch(new TokenRefresh($token, time()));
            }
        } else {
            $this->delete($token);
        }
    }

    public function delete($token)
    {
        [$hashKey,$hashListKey,$raw] = $this->tokenAnalysis($token);
        $token_info = $this->redis->hGet($hashListKey, $hashKey);
        $token_info = json_decode($token_info, true);
        if ($token_info['token'] == $token) {
            $this->redis->hDel($hashListKey, $hashKey);
        }
    }

    public function verify($token): array
    {
        $raw_token = $this->getTokenInfo($token);
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

    private function tokenNumber(string $guard, int $uid)
    {
        $this->userAllToken($guard, $uid);
        return Context::get('TokenNum');
    }

    public function formatToken($token)
    {
        $token = explode('.', $token);
        $raw_data = json_decode(base64_decode($token[0]), true);
        $sign = $token[1] ?? '';
        $raw_data['sign'] = $sign;
        Context::set('format_token', $raw_data);
        return $raw_data;
    }

    public function userAllToken($guard, $id)
    {
        $it = null;
        $arr = [];
        $num = 0;
        while ($key_arr = $this->redis->hScan($this->redisHashListKey($guard), $it, $id . '-*',$this->max_login_num)) {
            foreach ($key_arr as $key => $value) {
                $arr[$key] = json_decode($value, true);
                $num++;
            }
        }
        Context::set('tokens', $arr);
        Context::set('TokenNum', $num);
        return $arr;
    }

    private function getOldToken(string $guard, int $uid)
    {
        $delKeys = [];
        $tokens = $this->userAllToken($guard, $uid);
        $number = count($tokens);
        $surplusToken = $number - $this->max_login_num;

        if ($surplusToken > 0) {
            $tokens_key = array_values($tokens);
            //return $tokens_key[$number]['token'];
            for ($i = 0; $i < $surplusToken; $i++) {
                $delKeys[] = $tokens_key[$i]['token'];
            }
        }
        return $delKeys;
    }

    private function delSurplusToken($guard, $uid)
    {
        $tokens = $this->getOldToken($guard, $uid);
        if(!empty($tokens)){
            foreach ($tokens as $token) {
                $this->delete($token);
            }
        }
    }

    public function generate(string $guard, int $uid)
    {
        $this->deleteExpireToken($guard, $uid);
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
        Context::set('raw_user_data', $raw_user_data);
        Context::set('token', $token);
        $this->save();
        $this->event->dispatch(new TokenCreate($token, $uid, $guard));
        return $token;
    }


    private function deleteExpireToken($guard, $uid)
    {
        $hashListKey = $this->config->get('auth.hash_list_key');
        $it = null;
        while ($arr = $this->redis->hScan($hashListKey, $it, $uid . '-*',$this->max_login_num)) {
            foreach ($arr as $key => $value) {
                $token_info = json_decode($value, true);
                if ($token_info['expire'] < time()) {
                    $this->redis->hDel($hashListKey, $key);
                }
            }
        }
    }

    private function save()
    {
        $raw_data = Context::get('raw_user_data');
        $token = Context::get('token');
        $raw_data['token'] = $token;
        [$hashKey,$hashListKey,$raw] = $this->tokenAnalysis($token);
        $this->redis->hSet($hashListKey,$hashKey, json_encode($raw_data));
    }

    private function hashKey($token)
    {
        $origin = Context::get('format_token') ?? $this->formatToken($token);
        return (string)$origin['uid'] . '-' . $origin['sign'];
    }

    private function redisHashListKey($guard): string
    {
        return (string)$this->hash_list_key . $guard;
    }

    private function tokenSign($origin_token)
    {
        return md5($origin_token . $this->key);
    }

    private function tokenAnalysis($token){
        $origin = Context::get('format_token') ?? $this->formatToken($token);
        $hashKey = (string)$origin['uid'] . '-' . $origin['sign'];
        $hashListKey = $this->hash_list_key . $origin['guard'];
        $token_raw = $origin;
        return compact('hashKey','hashListKey','token_raw');
    }
}