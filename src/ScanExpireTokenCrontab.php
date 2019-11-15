<?php


namespace Niexiawei\Auth;
use Hyperf\Contract\ConfigInterface;
use Hyperf\Crontab\Annotation\Crontab;
use Hyperf\Utils\WaitGroup;
use Psr\Container\ContainerInterface;

/**
 * Class ScanExpireTokenCrontab
 * @package Niexiawei\Auth
 * @Crontab(name="ScanExpireTokenCrontab",rule="*\/10 * * * *",singleton=true,onOneServer=true,callback="scan")
 */

class ScanExpireTokenCrontab
{
    private $config;
    private $redis;
    public function __construct(ContainerInterface $container)
    {
        $this->config = $container->get(ConfigInterface::class);
        $this->getRedisDb($container);
        //$this->redis = $container->get(\Redis::class);
    }

    public function getRedisDb(ContainerInterface $container){
        $settingDb = $this->config->get('auth.redis_db');
        $redis_config = $this->config->has('redis.'.$settingDb);
        if($redis_config){
            $this->redis = $container->get(\Redis::class)->get($settingDb);
        }else{
            $this->redis = $container->get(\Redis::class);
        }
    }

    public function scan(){
        $guards = $this->getTokenStorageHashList();
        $this->scanExpireToken($guards);
    }

    public function scanExpireToken(array $guard_hash_list){
        $wg = new WaitGroup();
        foreach ($guard_hash_list as $value){
            $wg->add();
            go(function ()use ($value,$wg){
                $this->scanHashToken($value);
                $wg->done();
            });
        }
        $wg->wait();
        var_dump(date('Y-m-d H:i:s').'扫描过期Token执行成功');
    }

    public function scanHashToken(string $hashKey){
        $it = null;
        while ($arr_key = $this->redis->hScan($hashKey,$it,'*')){
            foreach ($arr_key as $key => $value){
                $token_info = json_decode($value,true);
                if($token_info['raw']['expire'] < time()){
                    $this->redis->hDel($hashKey,$key);
                }
            }
        }
    }

    public function getTokenStorageHashList(){
        $redisHashListPrefix = $this->config->get('auth.hash_list_key');
        $it = null;
        $res = [];
        while ($arr_key = $this->redis->scan($it,$redisHashListPrefix.'*')){
            foreach ($arr_key as $key => $value){
                $res[] = $value;
            }
        }
        return $res;
    }
}