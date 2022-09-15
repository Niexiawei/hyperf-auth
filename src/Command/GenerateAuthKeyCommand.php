<?php

namespace Niexiawei\Auth\Command;

use Hyperf\Command\Command as AuthCommand;
use Hyperf\Utils\Str as HyperfUtilsStr;
use Psr\Container\ContainerInterface;

class GenerateAuthKeyCommand extends AuthCommand
{
    protected ContainerInterface $container;

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
        $f = fopen(BASE_PATH . '/auth_key', 'w+');
        fwrite($f, HyperfUtilsStr::random(32));
        fclose($f);
        $this->output->success("auth_key已生成，请重启服务!");
    }
}
