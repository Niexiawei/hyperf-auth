<?php


namespace Niexiawei\Auth\Event;


class TokenCreate
{
    public $token;
    public $id;
    public $guard;

    public function __construct($token,$id,$guard)
    {
        $this->token = $token;
        $this->id = $id;
        $this->guard = $guard;
    }
}