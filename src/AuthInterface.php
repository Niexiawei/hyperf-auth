<?php


namespace Niexiawei\Auth;


interface AuthInterface
{
    public function auth($guard);
    //需要先调用 auth 方法
    public function id();
    public function logout();
    public function login(object $user);
    public function check();
    //可单独使用
    public function formatToken();
    public function getToken();
}