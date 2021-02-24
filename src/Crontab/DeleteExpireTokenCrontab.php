<?php


namespace Niexiawei\Auth\Crontab;


use Carbon\Carbon;
use Hyperf\Crontab\Annotation\Crontab;
use Hyperf\Redis\Redis;
use Hyperf\Utils\ApplicationContext;
use Niexiawei\Auth\AuthUserObj;

/**
 * Class DeleteExpireTokenCrontab
 * @package Niexiawei\Auth\Crontab
 * @Crontab(name="DeleteAuthExpireTokenCrontab",rule="*\/20 * * * *",onOneServer=true,singleton=true,callback="handler")
 */
class DeleteExpireTokenCrontab
{
    public function handler()
    {
        $it = null;
        $redis = ApplicationContext::getContainer()->get(Redis::class);
        $del = [];

        $now = Carbon::now();

        while (true) {
            $arr = $redis->hScan('user_token_list', $it, '*');
            if ($arr === false) {
                break;
            }
            foreach ($arr as $key => $value) {
                $userObj = unserialize($value);
                if (!$userObj instanceof AuthUserObj) {
                    $del[] = $key;
                    continue;
                }
                $expireData = Carbon::parse($userObj->expire_date);

                if ($expireData < $now) {
                    $del[] = $key;
                }
            }
        }

        call_user_func_array([$redis, 'hDel'], ['user_token_list', ...$del]);
    }
}
