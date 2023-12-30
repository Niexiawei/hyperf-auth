<?php


namespace Niexiawei\Auth\Listener;

use Hyperf\Context\ApplicationContext;
use Hyperf\Contract\ConfigInterface;
use Hyperf\Event\Contract\ListenerInterface;
use Hyperf\Framework\Event\BeforeMainServerStart;
use Hyperf\Stringable\Str;

class InitAuthKeyListener implements ListenerInterface
{
    public function listen(): array
    {
        return [
            BeforeMainServerStart::class,
        ];
    }

    public function process(object $event): void
    {
        if ($event instanceof BeforeMainServerStart) {
            $app = ApplicationContext::getContainer();
            $config = $app->get(ConfigInterface::class);

            if (!file_exists(BASE_PATH . '/auth_key')) {
                $this->generateAuthKeyFile($config);
            } else {
                $key = file_get_contents(BASE_PATH . '/auth_key');
                $config->set('auth.key', $key);
            }
        }
    }

    private function generateAuthKeyFile(ConfigInterface $config)
    {
        $key = Str::random(32);
        $f = fopen(BASE_PATH . '/auth_key', 'w+');
        fwrite($f, $key);
        fclose($f);
        $config->set('auth.key', $key);
    }
}
