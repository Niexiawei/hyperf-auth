<?php


namespace Niexiawei\Auth\Annotation;


use Hyperf\Di\Annotation\AbstractAnnotation;
/**
 * @Annotation()
 * @Target({"CLASS", "METHOD"})
 */

class CheckUser extends AbstractAnnotation
{
    /**
     * @var bool
     */
    public $is_auth = true;
}