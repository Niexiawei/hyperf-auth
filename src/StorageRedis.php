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
        //->get($config->get('auth.redis_db'))
    }

    public function refresh(){

    }

    public function delete(){

    }

    public function verify(){

    }

    public function generate($guard, $uid)
    {
        $raw_user_data = [
            'guard' => $guard,
            'uid' => $uid,
            'time' => Carbon::now(),
            'expire' => Carbon::now()->addSeconds($this->expire),
            'random'=>Str::random(20),
            'refresh_expire' => Carbon::now()->addSeconds($this->refresh_expire),
        ];
        $token_start = base64_encode(json_encode($raw_user_data));
        $token_sign = $this->tokenSign($token_start);
        $token = $token_start.'.'.$token_sign;
        Context::set('raw_user_data',$raw_user_data);
        Context::set('token',$token);
        $this->save($guard,$uid);
        return $token;
    }

    private function save($guard,$uid){
        $redis_key = $this->redisHashListKey($guard);
        $raw_data = Context::get('raw_user_data');
        $token = Context::get('token');
        $this->redis->hSet($redis_key,$this->hashKey($uid),json_encode(['raw'=>$raw_data,'token'=>$token]));
    }

    private function hashKey($uid){
        return (string)$uid.Context::get('token_sign');
    }

    private function redisHashListKey($guard):string
    {
        return (string)$this->hash_list_key.$guard;
    }

    private function tokenSign($origin_token){
        $sign =  md5($origin_token.$this->key);
        Context::set('token_sign',$sign);
        return $sign;
    }
}