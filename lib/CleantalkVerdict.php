<?php

namespace CleanTalk;

class CleantalkVerdict
{
    public $allow = true;
    public $comment = '';
    public $error = '';
    public $request_link = null;

    /**
     * @var bool True if the verdict is made locally because the moderate server was unreachable
     */
    public $offline = false;

    public function getJSON()
    {
        return json_encode($this);
    }

    public function getArray()
    {
        return json_decode($this->getJSON(), true);
    }
}
