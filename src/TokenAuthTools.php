<?php


namespace MeigumiI\Auth;


use Carbon\Carbon;
use Hyperf\Contract\ConfigInterface;
use Hyperf\Utils\Str;

class TokenAuthTools
{

    private $request;
    private $expire;
    private $refresh_expire;
    private $key;
    private $max_login_num;

    public function __construct()
    {
        $this->request = authRequest();
        $this->expire = authConfig('auth.expire');
        $this->refresh_expire = authConfig('auth.refresh_expire');
        $this->key = authConfig('auth.key');
        $this->max_login_num = authConfig('auth.max_login_num');
    }

    public function verify($token)
    {
        $raw_token = $token;
        $token = explode('.',$token);
        if(!isset($token[1])){
            return false;
        }
        $raw_data = json_decode(base64_decode($token[0]),true);
        if(!$token[1] === $this->sign($raw_data)){
            return false;
        }
        $raw_data['sign'] = $token[1];
        $redis_token_verify = authRedis()->get($this->redisKey($raw_token));
        if(empty($redis_token_verify)){
            return false;
        }
        if ($redis_token_verify !== $raw_token){
            return false;
        }
        return true;
    }

    public function formatToken($token){
        $token = explode('.',$token);
        $raw_data = json_decode(base64_decode($token[0]),true);
        $sign = $token[1];
        $raw_data['sign'] = $sign;
        return $raw_data;
    }

    public function tokenRenewal($token){
        $key = $this->redisKey($token);
        if(!authRedis()->exists($key)){
            return false;
        }

        if(Carbon::parse($this->formatToken($token)['refresh_expire']) < Carbon::now()){
            return false;
        }
        $surplusTTL = authRedis()->ttl($key);
        if(!$surplusTTL > 3600 * 2){
            authRedis()->expire($key,3600 * 24);
        }
        return true;
    }

    public function redisKey($token){
        $token = explode('.',$token);
        if(!isset($token[1])){
            $sign = '';
        }else{
            $sign = $token[1];
        }
        $raw_data = json_decode(base64_decode($token[0]),true);
        $guard = $raw_data['guard'];
        $uid = $raw_data['uid'];
        return $guard.".".$uid.".".$sign;
    }
    public function saveRedis($token){
        $raw_token = $this->formatToken($token);
        $verify_key = $raw_token['guard'].".".$raw_token['uid'].'*';
        $now_token = authRedis()->keys($verify_key);
        if(count($now_token) >= $this->max_login_num){
            $del_index = random_int(0,(int)($this->max_login_num - 1));
            $del_token = $now_token[$del_index];
            authRedis()->del($del_token);
        }
        $token_key = $this->redisKey($token);
        authRedis()->setex($token_key,$this->expire,$token);
    }
    public function generate($guard, $uid)
    {
        $raw_user_data = [
            'guard' => $guard,
            'uid' => $uid,
            'time' => Carbon::now(),
            'expire' => Carbon::now()->addSeconds($this->expire),
            'random'=>Str::random(18),
            'refresh_expire' => Carbon::now()->addSeconds($this->refresh_expire),
        ];
        $token_start = base64_encode(json_encode($raw_user_data));
        $token_sign = $this->sign($raw_user_data);
        $token = $token_start.'.'.$token_sign;
        $this->saveRedis($token);
        return $token;
    }

    public function sign(array $rawData):string
    {
        foreach ($rawData as $key=>$value){
            $tmp[] = $key.'='.$value;
        }
        $tmp2 = implode('$',$tmp);
        return sha1($tmp2.$this->key);
    }

    public function getId($token):int
    {
        if($this->verify($token)){
            $raw_token = $this->formatToken($token);
            return $raw_token['uid'];
        }
        return 0;
    }

    public function getGuard($token)
    {
        if($this->verify($token)){
            $raw_token = $this->formatToken($token);
            return $raw_token['guard'];
        }
        return 0;
    }

    public function delToken($token){
        $key = $this->redisKey($token);
        authRedis()->del($key);
        return true;
    }
}