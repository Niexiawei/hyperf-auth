<?php


namespace Niexiawei\Auth;
use Hyperf\Contract\ConfigInterface;
use Hyperf\Crontab\Annotation\Crontab;
use Hyperf\Utils\WaitGroup;
use Niexiawei\Auth\Event\ExpireScanEvent;
use Psr\Container\ContainerInterface;
use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * Class ScanExpireTokenCrontab
 * @package Niexiawei\Auth
 * @Crontab(name="ScanExpireTokenCrontab",rule="*\/10 * * * *",singleton=true,onOneServer=true,callback="scan")
 */

class ScanExpireTokenCrontab
{
    private $config;
    private $redis;
    protected $event;
    public function __construct(ContainerInterface $container)
    {
        $this->config = $container->get(ConfigInterface::class);
        $this->redis = $container->get(\Redis::class);
        $this->event = $container->get(EventDispatcherInterface::class);
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
        $this->event->dispatch(new ExpireScanEvent());

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