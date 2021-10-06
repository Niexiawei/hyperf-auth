<?php

namespace Niexiawei\Auth;

use Hyperf\Utils\Str;

class AuthEncryption
{
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