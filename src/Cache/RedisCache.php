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
     * @param object $model
     * @param $user_id
     */

    public function set(object $model, $user_id, object $user)
    {
        $key = 'auth_cache:' . md5(serialize($model) . $user_id);

        $this->redis->setex($key, 3600, serialize($user));
    }

    /**
     * @param object $model
     * @param $user_id
     * @param false $refresh
     */

    public function get(object $model, $user_id)
    {
        $key = 'auth_cache:' . md5(serialize($model) . $user_id);
        $user_string = $this->redis->get($key);
        if (empty($user_string)) {
            $object = unserialize($user_string);
            if (is_object($object)) {
                return $object;
            }
        }
        return null;
    }
}
