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
        $this->user_token_list = env('APP_NAME').'_user_token_list';
    }
    public function config($key,$default = ''){
        return $this->configInterface->get('auth.'.$key,$default);
    }
    protected function redis()
    {
        $pool = $this->config('redis_pool','default');
        return $this->RedisFactory->get($pool);
    }
    private function tokenKey(string $token){
        $origin = $this->unFormat($token);
        $key = $origin['guard'].'_'.$origin['uid'].'_'.$token.'_'.$origin['create_time'];
        return $key;
    }
    protected function tokenSave(string $token){
        $this->delSurplusToken($token);
        $key = $this->tokenKey($token);
        $expire = $this->getTTL();
        $expire_timestamp = Carbon::now()->addSeconds($expire)->getTimestamp();
        $this->redis()->zAdd($this->user_token_list,[],$expire_timestamp,$key);
    }
    public function tokenExists(string $token):int
    {
        $key = $this->tokenKey($token);
        $expire = $this->redis()->zScore($this->user_token_list,$key);
        if(empty($expire)){
            return 0;
        }
        return $expire;
    }
    protected function getUidTokens(string $token){
        $tokens = [];
        $now = Carbon::now()->getTimestamp();
        $origin = $this->unFormat($token);
        $search = $origin['guard'].'_'.$origin['uid'].'_*';
        $it = null;
        $del_token = [];
        while (true){
            $arr = $this->redis()->zScan($this->user_token_list,$it,$search);
            if($arr === false){
                break;
            }
            foreach ($arr as $token_key => $expire){
                if($now > $expire){
                    $del_token[] = $token_key;
                }else{
                    $tokens[] = ['token_key'=>$token_key,'expire'=>$expire];
                }
            }
        }
        if(!empty($del_token)){
            $this->delToken(implode(',',$del_token));
        }
        return $tokens;
    }
    private function delToken($token){
        $this->redis()->zRem($this->user_token_list,$token);
    }
    public function generate(string $guard, int $uid)
    {
        $data = [
            'guard'=>$guard,
            'uid'=>$uid,
            'create_time'=>time(),
            'str'=>Str::random(32),
            'allow_refresh_token' => $this->getAllowRefreshToken() ? 1 : 0
        ];
        $token = $this->format($data);
        $this->tokenSave($token);
        return $token;
    }
    private function format(array $data){
        $key = $this->config('key');
        $token_head = base64_encode(json_encode($data));
        $token_sign = md5($token_head.$key);
        return $token_head.'.'.$token_sign;
    }
    private function unFormat(string $token){
        $origin = $this->tokenToOrigin($token);
        if(!empty($origin)){
            return $origin;
        }else{
            $origin = explode('.',$token);
            if(isset($origin[0]) && isset($origin[1])){
                $token_head = $origin[0];
                $token_sign = $origin[1];
                $origin_token = json_decode(base64_decode($token_head),true);
                $origin_token['sign'] = $token_sign;
                $this->tokenToOriginCache($token,$origin_token);
                return $origin_token;
            }
        }
        throw new Exception('Token无法解析');
    }
    private function getAllowRefreshToken(): bool
    {
        $allow = Context::get(AllowRefreshOrNotInterface::class,true);
        return  $allow;
    }
    public function delete($token){
        $keys = $this->tokenKey($token);
        $this->redis()->zRem($this->user_token_list,$keys);
    }
    private function getTTL()
    {
        $config = $this->config('expire', 3600 * 24);
        $second = Context::get(setTokenExpireInterface::class,$config);
        return $second;
    }
    private function delSurplusToken($token)
    {
        $tokens = $this->getUidTokens($token);
        $num = count($tokens);
        $max_num = $this->config('max_login_num',7) - 1;
        if($num > $max_num){
            $delNum = $num - $max_num;
            array_multisort(array_column($tokens,'expire'),SORT_ASC,$tokens);
            $delTokens = array_splice($tokens,0,$delNum);
            $del_token_arr = array_map(function ($tokens){
                return $tokens['token_key'];
            },$delTokens);
            if(!empty($del_token_arr)){
                var_dump($del_token_arr);
                foreach ($del_token_arr as $token){
                    $this->delToken($token);
                }
            }
        }
    }
    public function refresh($token)
    {
        $origin = $this->unFormat($token);
        $expire_timestamp = $this->tokenExists($token);
        $token_key = $this->tokenKey($token);
        $create_time = Carbon::createFromTimestamp($origin['create_time']);
        $expire_time = Carbon::createFromTimestamp($expire_timestamp);
        $max_login_time = $this->config('max_login_time',3600 * 24);
        if($create_time->diffInSeconds($create_time) <= $max_login_time){
            $expire = $expire_time->addSeconds($this->getTTL())->getTimestamp();
            $this->redis()->zAdd($this->user_token_list,[],$expire,$token_key);
        }
    }
    public function verify($token): array
    {
        $expire = $this->tokenExists($token);
        if($expire <= 0){
            return  [];
        }
        return $this->unFormat($token);
    }
    public function formatToken($token)
    {
        return $this->unFormat($token);
    }

    private function tokenToOriginCache($token,$orgin){
        $token_cache = Context::get('tokens_cache',[]);
        Context::set('tokens_cache',array_merge($token_cache,[$token=>$orgin]));
    }

    private function tokenToOrigin($token){
        $token_cache = Context::get('tokens_cache',[]);
        return $token_cache[$token] ?? [];
    }
}
