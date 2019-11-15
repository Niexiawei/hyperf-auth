<?php

use Hyperf\Utils\ApplicationContext;
use Niexiawei\Auth\AuthInterface as Auth;

if (!function_exists('auth')) {
    function auth()
    {
       $auth =  ApplicationContext::getContainer()->get(Auth::class);
       return $auth;
    }
}

