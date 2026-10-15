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

    public function getJSON()
    {
        return json_encode($this);
    }

    public function getArray()
    {
        return json_decode($this->getJSON(), true);
    }
}
