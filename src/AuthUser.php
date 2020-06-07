<?php


namespace Niexiawei\Auth;


trait AuthUser
{
    public function authFindColumn():array 
    {
        return ['*'];
    }
    
    public function getId()
    {
        return $this->id;
    }
    
    public function authFind($id){
        return self::find($id,$this->authFindColumn());
    }
}
