<?php


namespace Niexiawei\Auth;


use Swoole\Table;

class SwooleTableIncr
{
    public Table $table;

    public function init()
    {
        $table = new Table(1024);
        $table->column('num', Table::TYPE_INT);
        $table->create();
        $this->table = $table;
        $this->table->set('num', ['num' => 0]);
    }
    
    public function addIncr()
    {
        $this->table->incr('num', 'num');
    }

    public function initNum()
    {
        $this->table->set('num', ['num' => 0]);
    }

    public function getNum()
    {
        return $this->table->get('num', 'num');
    }
}
