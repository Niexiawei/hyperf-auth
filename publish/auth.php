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
    'refresh_expire'=>3600 * 24 *30,//token最长有效期
    'key'=>'key', //务必设置新的key
    'max_login_num'=>7,
];
