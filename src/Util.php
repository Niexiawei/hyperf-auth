<?php


namespace Niexiawei\Auth;


use Hyperf\Contract\ConfigInterface;
use Hyperf\Utils\ApplicationContext;

class Util
{

    public function config()
    {
        $config = ApplicationContext::getContainer()->get(ConfigInterface::class);
        return $config->get('auth');
    }

    public function encryption($data)
    {
        return base64_encode(openssl_encrypt($data, 'DES-ECB', $this->config()['key']));
    }

    public function decrypt($data)
    {
        return openssl_decrypt(base64_decode($data), 'DES-ECB', $this->config()['key']);
    }
}
