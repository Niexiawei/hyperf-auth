<?php


namespace Niexiawei\Auth\Listener;


use Hyperf\Contract\ConfigInterface;
use Hyperf\Contract\StdoutLoggerInterface;
use Hyperf\Event\Contract\ListenerInterface;
use Hyperf\Framework\Event\BeforeServerStart;
use Hyperf\Utils\ApplicationContext;

class InitAuthKeyListener implements ListenerInterface
{
    public function listen(): array
    {
        return [
            BeforeServerStart::class,
        ];
    }

    public function process(object $event)
    {
        if ($event instanceof BeforeServerStart) {
            $app = ApplicationContext::getContainer();
            $config = $app->get(ConfigInterface::class);

            if (!file_exists(BASE_PATH . '/auth_key')) {
                di(StdoutLoggerInterface::class)->error("key文件不存在，请使用命令生成;如未生成key文件会产生意料之外的错误。");
                di(StdoutLoggerInterface::class)->warning("使用命令(generate:auth_key)生成key文件。");
                return;
            }

            $key = file_get_contents(BASE_PATH . '/auth_key');
            $config->set('auth.key', $key);
        }
    }
}
