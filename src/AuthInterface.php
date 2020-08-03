<?php


namespace Niexiawei\Auth;


interface AuthInterface
{
    public function id();
    public function logout();
    public function login(string $guard,object $user);
    public function check();
    public function user():object ;
    public function formatToken();
    public function getToken();
    public function setToken($token):Auth;
    public function setTTL(int $second):Auth;
    public function setAllowRefreshToken(bool $allow = true):Auth;
    public function guard();
    public function refresh();
}
