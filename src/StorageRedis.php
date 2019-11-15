<?php


namespace Niexiawei\Auth;


use Carbon\Carbon;
use Hyperf\Contract\ConfigInterface;
use Hyperf\Utils\Context;
use Hyperf\Utils\Str;
use Psr\Container\ContainerInterface;

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

    public function __construct(ContainerInterface $container)
    {
        $this->config = $config =  $container->get(ConfigInterface::class);
        $this->expire = $config->get('auth.expire',3600 * 24);
        $this->refresh_expire = $config->get('auth.refresh_expire',3600 * 24 * 30);
        $this->key = $config->get('auth.key');
        $this->max_login_num = $config->get('auth.max_login_num',7);
        $this->surplus = $config->get('auth.surplus',60 * 2);
        $this->renewal = $config->get('auth.renewal',3600 * 12);
        $this->hash_list_key = $config->get('auth.hash_list_key','user_token');
        $this->redis = $container->get(\Redis::class);
    }

    private function getTokenInfo($token){
        $origin = $this->formatToken($token);
        $raw_token = $this->redis->hGet($this->redisHashListKey($origin['guard']),$this->hashKey($token));
        if(empty($raw_token)){
            return [];
        }
        return json_decode($raw_token,true);
    }

    public function refresh($token){
        $raw_token = $this->getTokenInfo($token);
        $user_info = $raw_token['raw'];
        if($user_info['refresh_expire'] > Carbon::now()->getTimestamp()){
           if($user_info['expire'] - Carbon::now()->getTimestamp() < $this->surplus){
               $user_info['expire'] = Carbon::now()->addSeconds($this->renewal)->getTimestamp();
               $redis_key = $this->redisHashListKey($user_info['guard']);
               $this->redis->hSet($redis_key,$this->hashKey($token),json_encode(['raw'=>$user_info,'token'=>$token]));
           }
        }
    }

    public function delete($token){
        $origin = $this->formatToken($token);
        $key = $this->redisHashListKey($origin['guard']);
        $hashKey = $this->hashKey($token);
        $token_info = $this->redis->hGet($key,$hashKey);
        $token_info = json_decode($token_info,true);
        if($token_info['token'] == $token){
            $this->redis->hDel($key,$hashKey);
        }
    }

    public function verify($token):array
    {
        $raw_token = $this->getTokenInfo($token);
        if(empty($raw_token)){
            return [];
        }
        if($token !== $raw_token['token']){
            return [];
        }
        if(Carbon::now()->getTimestamp() > $raw_token['raw']['expire']){
            return  [];
        }
        $this->refresh($token);
        return  $raw_token['raw'];
    }

    private function tokenNumber(string $guard,int $uid){
        $tokens = $this->userAllToken($guard,$uid);
        return count($tokens);
    }

    public function formatToken($token){
        $token = explode('.',$token);
        $raw_data = json_decode(base64_decode($token[0]),true);
        $sign = $token[1] ?? '';
        $raw_data['sign'] = $sign;
        Context::set('format_token',$raw_data);
        return $raw_data;
    }
    public function userAllToken($guard,$id){
        $it = null;
        $arr = [];
        while ($key_arr = $this->redis->hScan($this->redisHashListKey($guard),$it,$id.'-*')){
            foreach ($key_arr as $key => $value){
                $arr[$key] = json_decode($value,true);
            }
        }
        Context::set('tokens',$arr);
        return $arr;
    }

    private function getOldToken(string $guard,int $uid){
        $tokens = $this->userAllToken($guard,$uid);
        $number = count($tokens) - 1;
        if($number > 0){
            $tokens_key = array_values($tokens);
            return $tokens_key[$number]['token'];
        }
        return '';
    }

    public function generate(string $guard,int $uid)
    {
        $raw_user_data = [
            'guard' => $guard,
            'uid' => $uid,
            'create_time' => Carbon::now()->getTimestamp(),
            'expire' => Carbon::now()->addSeconds($this->expire)->getTimestamp(),
            'random'=>Str::random(20),
            'refresh_expire' => Carbon::now()->addSeconds($this->refresh_expire)->getTimestamp(),
        ];
        $token_start = base64_encode(json_encode($raw_user_data));
        $token_sign = $this->tokenSign($token_start);
        $token = $token_start.'.'.$token_sign;
        Context::set('raw_user_data',$raw_user_data);
        Context::set('token',$token);
        if($this->tokenNumber($guard,$uid) >= $this->max_login_num){
            $oldToken = $this->getOldToken($guard,$uid);
            if(!empty($oldToken)){
                $this->delete($oldToken);
            }
        }
        $this->save();
        return $token;
    }

    private function save(){
        $raw_data = Context::get('raw_user_data');
        $token = Context::get('token');
        $redis_key = $this->redisHashListKey($raw_data['guard']);
        $this->redis->hSet($redis_key,$this->hashKey($token),json_encode(['raw'=>$raw_data,'token'=>$token]));
    }

    private function hashKey($token){
        $origin = Context::get('format_token') ?? $this->formatToken($token);
        return (string)$origin['uid'].'-'.$origin['sign'];
    }

    private function redisHashListKey($guard):string
    {
        return (string)$this->hash_list_key.$guard;
    }

    private function tokenSign($origin_token){
        return md5($origin_token.$this->key);
    }
}