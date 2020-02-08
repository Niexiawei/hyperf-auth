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
    'guards'=>[

    ],
    'expire'=>3600 * 24,//token过期时间
    'key'=>'key', //务必设置新的key
    'max_login_num' => 7, // 最大登录客户端
    'storage_prefix'=>'user_token_',
    'max_login_time'=>3600 * 24 * 30,
    'redis_pool'=>'default'
];
