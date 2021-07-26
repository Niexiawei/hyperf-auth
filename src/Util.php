<?php


namespace Niexiawei\Auth;


use Hyperf\Config\Annotation\Value;
use Hyperf\Contract\ConfigInterface;
use Hyperf\Utils\ApplicationContext;
use Hyperf\Utils\Str;

class Util
{
    public $method = 'aes-256-cbc';

    /**
     * @var array
     * @Value("auth")
     */
    protected $auth_config;

    private function key()
    {
        $key = $this->auth_config['key'];
        if (mb_strlen($key) <= 0) {
            throw new \Exception("key文件不存在，请手动使用命令生成");
        }
        return $key;
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
