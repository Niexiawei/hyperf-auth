<?php


namespace Niexiawei\Auth;


class TokenAuthDrive
{

    private $guard;
    private $token;
    private $userModel;
    private $tools;
    public function __construct($guard,$token,object $model)
    {
        $this->guard = $guard;
        $this->token = $token;
        $this->userModel = $model;
        $this->tools = new TokenAuthTools();
    }

    public function user(){
        $uid = $this->tools->getId($this->token);
        if($uid === 0){
            return [];
        }
        $user = $this->userModel->where('id',$uid)->first();
        if(!empty($user)){
            $this->tools->tokenRenewal($this->token);
        }
        return $user;
    }

    public function check(){
        $uid = $this->tools->getId($this->token);
        if($uid != 0){
            $this->tools->tokenRenewal($this->token);
        }
        return $uid == 0 ? false:true;
    }

    public function id(){
        return $this->tools->getId($this->token);
    }
    public function logout(){
        $this->tools->delToken($this->token);
        return true;
    }

    public function login(object $user){
        $id = $user->id;
        return $this->tools->generate($this->guard,$id);
    }
}