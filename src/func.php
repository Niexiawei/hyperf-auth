<?php

use Hyperf\Utils\ApplicationContext;
use Niexiawei\Auth\AuthInterface as Auth;

if (!function_exists('auth')) {
    function auth($guard)
    {
        $Auth = ApplicationContext::getContainer()->get(Auth::class);
        return $Auth->auth($guard);
    }
}

