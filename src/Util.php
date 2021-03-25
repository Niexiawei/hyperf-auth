<?php


namespace Niexiawei\Auth;


use Hyperf\Contract\ConfigInterface;
use Hyperf\Utils\ApplicationContext;
use Hyperf\Utils\Str;

class Util
{
    public $method = 'aes-256-cbc';

    public function config()
    {
        $config = ApplicationContext::getContainer()->get(ConfigInterface::class);
        return $config->get('auth');
    }

    private function key()
    {
        return $this->config()['key'];
    }

    private function iv()
    {
        return Str::substr($this->key() . '0000000000000000', 0, 16);
    }

    public function encryption($data)
    {
        return base64_encode(openssl_encrypt($data, $this->method, $this->key(), 0, $this->iv()));
    }

    public function decrypt($data)
    {
        return openssl_decrypt(base64_decode($data), $this->method, $this->key(), 0, $this->iv());
    }
}
