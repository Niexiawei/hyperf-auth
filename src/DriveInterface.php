<?php


namespace Niexiawei\Auth;


interface DriveInterface
{
    public function generate(string $guard,int $uid);
    public function delete($token);
    public function refresh(AuthUserObj $userObj);
    public function verify($token):AuthUserObj;
}
