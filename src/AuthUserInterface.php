<?php


namespace Niexiawei\Auth;


interface AuthUserInterface
{
    public function authFindColumn(): array;

    public function getId();

    public function authFind($id, $column = null);
}
