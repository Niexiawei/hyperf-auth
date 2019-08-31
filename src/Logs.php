<?php


namespace MeigumiI\Auth;


use Monolog\Handler\StreamHandler;
use Monolog\Logger;
use Monolog\Handler\FirePHPHandler;

class Logs
{

    private $logs;
    public function __construct()
    {
        $this->logs = new Logger('auth_logs');
    }

    public function logs(){
        $this->logs->pushHandler(new StreamHandler(BASE_PATH.'/logs/auth.log', Logger::DEBUG));
        $this->logs->pushHandler(new FirePHPHandler());
        return $this->logs;
    }
}