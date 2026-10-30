<?php

namespace CleanTalk;

class CleantalkVerdict
{
    /**
     * Whether the request is allowed, 1|0.
     *
     * @var int
     */
    public $allow = 1;
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
