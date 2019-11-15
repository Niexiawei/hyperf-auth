<?php


namespace Niexiawei\Annotation;


use Hyperf\Di\Annotation\AbstractAnnotation;
/**
 * @Annotation()
 * @Target({"CLASS", "METHOD"})
 */

class Auth extends AbstractAnnotation
{
    /**
     * @var bool
     */
    public $is_auth = true;

    public function __construct($value = null)
    {
        parent::__construct($value);
    }
}