<?php


namespace Niexiawei\Auth;


use Hyperf\Config\Annotation\Value;
use Hyperf\Context\Context;
use Hyperf\Stringable\Str;

class Util
{
    public string $method = 'aes-256-cbc';

    #[Value("auth")]
    protected array $auth_config;

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

    public static function encryption($data)
    {
        return base64_encode(openssl_encrypt($data, self::selfClass()->method, self::selfClass()->key(), 0, self::selfClass()->iv()));
    }

    public static function decrypt($data)
    {
        return openssl_decrypt(base64_decode($data), self::selfClass()->method, self::selfClass()->key(), 0, self::selfClass()->iv());
    }

    public static function selfClass(): static
    {
        $self = Context::get(static::class . '_selfClass', null);
        if (!$self) {
            $self = new self();
            Context::set(static::class . '_selfClass', $self);
            return $self;
        }

        return $self;
    }
}
