<?php


namespace Niexiawei\Auth;


interface AuthInterface
{
    public function id();
    public function logout();
    public function login(string $guard,object $user);
    public function check();
    public function user();
    public function formatToken();
    public function getToken();
    public function setToken($token):Auth;
    public function guard();
}