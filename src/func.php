<?php

use Hyperf\Utils\ApplicationContext;
use Niexiawei\Auth\AuthInterface as Auth;

if (!function_exists('auth')) {
    function auth()
    {
       return ApplicationContext::getContainer()->get(Auth::class);
    }
}

