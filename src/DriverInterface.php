<?php


namespace Niexiawei\Auth;


interface DriverInterface
{
    public function generate(string $guard,int $uid);
    public function delete($token);
    public function refresh($token);
    public function verify($token):AuthUserObj;
}
