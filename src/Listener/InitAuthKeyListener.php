<?php


namespace Niexiawei\Auth\Listener;


use Hyperf\Contract\ConfigInterface;
use Hyperf\Contract\StdoutLoggerInterface;
use Hyperf\Event\Contract\ListenerInterface;
use Hyperf\Framework\Event\BeforeMainServerStart;
use Hyperf\Framework\Event\BeforeServerStart;
use Hyperf\Utils\ApplicationContext;

class InitAuthKeyListener implements ListenerInterface
{
    public function listen(): array
    {
        return [
            BeforeMainServerStart::class,
        ];
    }

    public function process(object $event)
    {
        if ($event instanceof BeforeMainServerStart) {
            $app = ApplicationContext::getContainer();
            $config = $app->get(ConfigInterface::class);

            if (!file_exists(BASE_PATH . '/auth_key')) {
                $app->get(StdoutLoggerInterface::class)->error("auth_key文件不存在，使用命令(generate:auth_key)生成auth_key文件不存在文件。");
                return;
            }

            $key = file_get_contents(BASE_PATH . '/auth_key');
            $config->set('auth.key', $key);
        }
    }
}
