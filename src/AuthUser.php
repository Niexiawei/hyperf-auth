<?php


namespace Niexiawei\Auth;


trait AuthUser
{
    public function authFindColumn(): array
    {
        return ['*'];
    }

    public function getId()
    {
        return $this->id;
    }

    public function authFind($id, $cloumn = null)
    {

        if (empty($cloumn) || is_null($cloumn)) {
            $cloumn = $this->authFindColumn();
        }

        return self::find($id, $cloumn);
    }
}
