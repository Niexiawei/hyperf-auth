<?php


namespace MeigumiI\Auth;

use MeigumiI\Auth\Exception\GuardNothingnessException;

class Auth
{
    public function auth($guard){
        $model = $this->getModel($guard);
        if(empty($model)){
            logs()->error('guard不存在');
            throw new GuardNothingnessException('guard不存在');
        }
        return new TokenAuthDrive($guard,$this->getToken(),$this->getModel($guard));
    }

    public function getModel($guard){
       return authConfig('auth.guards.'.$guard.'.model');
    }

    public function getToken(){
        $request = authRequest();
        if($request->has('token')){
            return $request->input('token');
        }elseif ($request->hasHeader('token')){
            return $request->header('token');
        }else{
            return '';
        }
    }
}