<?php

/*
 *  guards 配置格式
 * [
 *    'auth'=>[
 *         'model'=>'app/Models/User::class'
 *     ]
 * ]
 *
 *
 */
return [
    'guards' => [

    ],
    'expire' => 3600 * 24,//token过期时间
    'key' => '',
    'max_login_num' => 7, // 最大登录客户端
    'allow_timeout_refresh' => 60,
    'redis_pool' => 'auth',
    'driver' => \Niexiawei\Auth\Driver\RedisDriver::class
];
