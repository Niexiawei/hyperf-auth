<?php


namespace MeigumiI\Auth;


interface AuthInterface
{
    public function auth($guard);
    public function getModel($guard);
    public function getToken();
}