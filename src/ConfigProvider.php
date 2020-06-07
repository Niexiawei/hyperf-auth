<?php

declare(strict_types=1);
/**
 * This file is part of Hyperf.
 *
 * @link     https://www.hyperf.io
 * @document https://doc.hyperf.io
 * @contact  group@hyperf.io
 * @license  https://github.com/hyperf-cloud/hyperf/blob/master/LICENSE
 */

namespace Niexiawei\Auth;

use Niexiawei\Auth\Command\GenerateAuthKeyCommand;
use Niexiawei\Auth\Listener\AppBootListener;

class ConfigProvider
{
    public function __invoke(): array
    {
        return [
            'dependencies' => [
                AuthInterface::class => Auth::class
            ],
            'commands' => [
                GenerateAuthKeyCommand::class
            ],
            'annotations' => [
                'scan' => [
                    'paths' => [
                        __DIR__,
                    ],
                ],
            ],
            'listeners' => [
                AppBootListener::class
            ],
            'publish' => [
                [
                    'id' => 'config',
                    'description' => 'hyperf-auth 配置文件',
                    'source' => __DIR__ . '/../publish/auth.php',
                    'destination' => BASE_PATH . '/config/autoload/auth.php',
                ],
            ],
        ];
    }
}
