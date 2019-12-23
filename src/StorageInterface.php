<?php


namespace Niexiawei\Auth;


interface StorageInterface
{
    public function generate(string $guard,int $uid);
    public function delete($token);
    public function refresh($token);
    public function verify($token):array;
    public function formatToken($token);
}
