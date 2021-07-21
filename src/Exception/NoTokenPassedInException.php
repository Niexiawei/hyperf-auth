<?php


namespace Niexiawei\Auth\Exception;


class NoTokenPassedInException extends \Exception
{
    protected $message = '还没有传入Token';
}
