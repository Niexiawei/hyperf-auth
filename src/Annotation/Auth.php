<?php


namespace Niexiawei\Auth\Annotation;

use Attribute;
use Hyperf\Di\Annotation\AbstractAnnotation;
/**
 * @Annotation()
 * @Target({"CLASS", "METHOD"})
 */
#[Attribute(Attribute::TARGET_METHOD,Attribute::TARGET_CLASS)]
class Auth extends AbstractAnnotation
{

}
