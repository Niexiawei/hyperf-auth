<?php

namespace Niexiawei\Auth\Listener;

use Hyperf\Event\Contract\ListenerInterface;
use Hyperf\Framework\Event\BeforeWorkerStart;
use Hyperf\Utils\ApplicationContext;
use Hyperf\Contract\ConfigInterface;

class AppBootListener implements ListenerInterface
{
    public function listen(): array
    {
        return [
            BeforeWorkerStart::class
        ];
    }

    public function process(object $event)
    {
        $app = ApplicationContext::getContainer();
        $config = $app->get(ConfigInterface::class);
        $key = file_get_contents(BASE_PATH . '/auth_key');
        $config->set('auth.key', $key);
    }

}
