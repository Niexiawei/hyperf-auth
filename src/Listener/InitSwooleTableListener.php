<?php


namespace Niexiawei\Auth\Listener;


use Hyperf\Event\Contract\ListenerInterface;
use Hyperf\Framework\Event\BootApplication;
use Hyperf\Utils\ApplicationContext;
use Niexiawei\Auth\SwooleTableIncr;

class InitSwooleTableListener implements ListenerInterface
{
    public function listen(): array
    {
        return [
            BootApplication::class
        ];
    }

    public function process(object $event)
    {
        if ($event instanceof BootApplication){
            ApplicationContext::getContainer()->get(SwooleTableIncr::class)->init();
        }
    }

}
