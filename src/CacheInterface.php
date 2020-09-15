<?php


namespace Niexiawei\Auth;


interface CacheInterface
{
    public function set(object $model, $user_id, object $user);
    public function get(object $model, $user_id);
}
