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
    'max_login_time' => 3600 * 24 * 30,
    'redis_pool' => 'auth',
    'drive' => \Niexiawei\Auth\Drive\RedisDrive::class
];
