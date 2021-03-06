<?php

namespace Niexiawei\Auth\Command;

use Hyperf\Command\Command as AuthCommand;
use Psr\Container\ContainerInterface;

class GenerateAuthKeyCommand extends AuthCommand
{
    /**
     * @var ContainerInterface
     */
    protected $container;

    public function __construct(ContainerInterface $container)
    {
        $this->container = $container;

        parent::__construct('generate:auth_key');
    }

    public function configure()
    {
        parent::configure();
        $this->setDescription('生成auth的加密秘钥');
    }

    public function handle()
    {
        $f = fopen(BASE_PATH.'/auth_key','w+');
        fwrite($f,\Hyperf\Utils\Str::random(32));
        fclose($f);
        $this->line('成功');
    }
}
