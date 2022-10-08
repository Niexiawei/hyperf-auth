<?php

namespace Niexiawei\Auth\Cache;

use Hyperf\Di\Annotation\Inject;
use Hyperf\Redis\Redis;
use Niexiawei\Auth\CacheInterface;
use RedisException;

class RedisCache implements CacheInterface
{

    #[Inject]
    protected Redis $redis;

    /**
     * @param string $guard
     * @param int $user_id
     * @param object $user
     * @throws RedisException
     */

    public function set(string $guard, $user_id, object $user): void
    {
        $key = 'auth_cache:' . $guard . '_' . $user_id;
        $this->redis->setex($key, 3600, serialize($user));
    }

    /**
     * @param string $guard
     * @param int $user_id
     * @return object|null
     * @throws RedisException
     */

    public function get(string $guard, $user_id): ?object
    {
        $key = 'auth_cache:' . $guard . '_' . $user_id;

        $user_string = $this->redis->get($key);
        if ($user_string) {
            $object = unserialize($user_string);
            if (is_object($object)) {
                return $object;
            }
        }
        return null;
    }
}
