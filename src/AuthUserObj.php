<?php


namespace Niexiawei\Auth;


use Carbon\Carbon;
use Hyperf\Snowflake\IdGeneratorInterface;
use Hyperf\Context\ApplicationContext;
use Hyperf\Stringable\Str;

class AuthUserObj
{
    public int $user_id;
    public string $guard;
    public string $create_date;
    public string $expire_date;
    public bool $allow_refresh_token;
    public string $str;
    public int $id;

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

    private function setId(): int
    {
        return ApplicationContext::getContainer()->get(IdGeneratorInterface::class)->generate();
    }
}
