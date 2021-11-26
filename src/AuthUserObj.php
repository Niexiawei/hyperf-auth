<?php


namespace Niexiawei\Auth;


use Carbon\Carbon;
use Hyperf\Snowflake\IdGeneratorInterface;
use Hyperf\Utils\ApplicationContext;
use Hyperf\Utils\Str;

class AuthUserObj
{
    public $user_id;
    public $guard;
    public $create_date;
    public $expire_date;
    public $allow_refresh_token;
    public $str;

    public function __construct(int $user_id, string $guard, int $expire_sec, bool $allow_refresh_token)
    {
        $this->user_id = $user_id;
        $this->guard = $guard;
        $this->create_date = Carbon::now()->toDateTimeString();
        $this->expire_date = Carbon::now()->addSeconds($expire_sec)->toDateTimeString();
        $this->allow_refresh_token = $allow_refresh_token;
        $this->str = Str::random(32) . ':' . uniqid();
        $this->id = $this->setId();
    }

    private function setId()
    {
        return ApplicationContext::getContainer()->get(IdGeneratorInterface::class)->generate();
    }
}
