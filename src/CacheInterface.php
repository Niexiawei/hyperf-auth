<?php


namespace Niexiawei\Auth;


interface CacheInterface
{
    public function set(string $guard, $user_id, object $user);
    public function get(string $guard, $user_id);
}
