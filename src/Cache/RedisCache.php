<?php

namespace Niexiawei\Auth\Cache;

use Hyperf\Di\Annotation\Inject;

class RedisCache
{
    /**
     * @Inject()
     * @var \Redis
     */

    protected $redis;

    /**
     * @param string $gurad
     * @param int $user_id
     */

    public function set($gurad, $user_id, object $user)
    {
        $key = 'auth_cache:' . $gurad.'_'.$user_id;
        $this->redis->setex($key, 3600, serialize($user));
    }

    /**
     * @param string $gurad
     * @param int $user_id
     * @param false $refresh
     */

    public function get($gurad, $user_id)
    {
        $key = 'auth_cache:' . $gurad.'_'.$user_id;

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
