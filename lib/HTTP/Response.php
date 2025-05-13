<?php

namespace CleanTalk\HTTP;

class Response
{
    private $raw;
    private $processed;
    private $error;
    private $info;
    private $response_code;

    /**
     * HTTPResponse constructor.
     *
     * @param $raw
     * @param $info
     */
    public function __construct($raw, $info)
    {
        $this->raw       = $raw;
        $this->processed = $raw;
        $this->info      = $info;
        $this->error     = ! empty($raw['error'])
            ? $raw
            : null;
        if ( isset($this->info['http_code']) ) {
            $this->response_code = (int)$this->info['http_code'];
        }
    }

    /**
     * @return mixed
     */
    public function getError()
    {
        return $this->error;
    }

    /**
     * @return mixed
     */
    public function getResponseCode()
    {
        return $this->response_code;
    }

    /**
     * @return mixed
     */
    public function getContentRaw()
    {
        return $this->raw;
    }

    /**
     * @return mixed
     */
    public function getContentProcessed()
    {
        return $this->processed;
    }

    /**
     * @param mixed $processed
     */
    public function setProcessed($processed)
    {
        $this->processed = $processed;
    }

    /**
     * @return mixed
     */
    public function getInfo()
    {
        return $this->info;
    }
}
