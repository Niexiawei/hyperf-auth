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

    public function authFind($id, $column = null)
    {

        if (empty($cloumn) || is_null($column)) {
            $column = $this->authFindColumn();
        }

        return self::find($id, $column);
    }
}
