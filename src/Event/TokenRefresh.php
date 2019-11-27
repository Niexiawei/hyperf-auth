<?php


namespace Niexiawei\Auth\Event;


class TokenRefresh
{
    public $token;
    public $time;

    public function __construct($token,$time)
    {
        $this->token = $token;
        $this->time = $time;
    }
}