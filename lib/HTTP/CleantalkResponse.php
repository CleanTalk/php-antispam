<?php

namespace CleanTalk\HTTP;

/**
 * Response class
 * @psalm-suppress PossiblyUnusedProperty
 */
class CleantalkResponse
{
    /**
     * Received feedback number
     * @var int
     */
    public $received;

    /**
     *  Is stop words
     * @var null|string
     */
    public $stop_words;

    /**
     * Cleantalk comment
     * @var null|string
     */
    public $comment;

    /**
     * Is blacklisted
     * @var int
     */
    public $blacklisted;

    /**
     * Is allow, 1|0
     * @var int
     */
    public $allow;

    /**
     * Request ID
     * @var int
     */
    public $id;

    /**
     * Request errno
     * @var int
     */
    public $errno;

    /**
     * Error string
     * @var string
     */
    public $errstr;

    /**
     * Is fast submit, 1|0
     * @var string
     */
    public $fast_submit;

    /**
     * Is spam comment
     * @var string
     */
    public $spam;

    /**
     * Is JS
     * @var int
     */
    public $js_disabled;

    /**
     * Sms check
     * @var int
     */
    public $sms_allow;

    /**
     * Sms code result
     * @var int
     */
    public $sms;

    /**
     * Sms error code
     * @var int
     */
    public $sms_error_code;

    /**
     * Sms error code
     * @var string
     */
    public $sms_error_text;

    /**
     * Stop queue message, 1|0
     * @var int
     */
    public $stop_queue;

    /**
     * Account should by deactivated after registration, 1|0
     * @var int
     */
    public $inactive;

    /**
     * Account status
     * @var int
     */
    public $account_status = -1;

    /**
     * @var array Contains codes returned from server
     */
    public $codes = array();

    /**
     * @var null|array Contains a error
     */
    public $error = null;

    /**
     * @var string Failed connections array data
     */
    public $failed_connections_urls_string = '';

    /**
     * Create server response
     *
     * @param object $obj
     * @param null|string $failed_urls
     */
    public function __construct($obj = null, $failed_urls = null)
    {
        $this->errno          = isset($obj->errno) ? $obj->errno : 0;
        $this->errstr         = isset($obj->errstr) ?
            preg_replace("/.+(\*\*\*.+\*\*\*).+/", "$1", htmlspecialchars($obj->errstr)) :
            null;
        $this->stop_words     = isset($obj->stop_words) ? Helper::fromUTF8($obj->stop_words, 'ISO-8859-1') : null;
        $this->comment        = isset($obj->comment) ? strip_tags(Helper::fromUTF8($obj->comment, 'ISO-8859-1'), '<p><a><br>') : null;
        $this->blacklisted    = isset($obj->blacklisted) ? $obj->blacklisted : null;
        $this->allow          = isset($obj->allow) ? $obj->allow : 1;
        $this->id             = isset($obj->id) ? $obj->id : null;
        $this->fast_submit    = isset($obj->fast_submit) ? $obj->fast_submit : 0;
        $this->spam           = isset($obj->spam) ? $obj->spam : 0;
        $this->js_disabled    = isset($obj->js_disabled) ? $obj->js_disabled : 0;
        $this->sms_allow      = isset($obj->sms_allow) ? $obj->sms_allow : null;
        $this->sms            = isset($obj->sms) ? $obj->sms : null;
        $this->sms_error_code = isset($obj->sms_error_code) ? $obj->sms_error_code : null;
        $this->sms_error_text = isset($obj->sms_error_text) ? htmlspecialchars($obj->sms_error_text) : '';
        $this->stop_queue     = isset($obj->stop_queue) ? $obj->stop_queue : 0;
        $this->inactive       = isset($obj->inactive) ? $obj->inactive : 0;
        $this->account_status = isset($obj->account_status) ? $obj->account_status : -1;
        $this->received       = isset($obj->received) ? $obj->received : -1;
        $this->codes          = isset($obj->codes) ? explode(' ', $obj->codes) : array();

        if ( $this->errno !== 0 && $this->errstr !== null && $this->comment === null ) {
            $this->comment = '*** ' . $this->errstr . ' Anti-Spam service cleantalk.org ***';
        }

        $this->failed_connections_urls_string = !empty($failed_urls) ? $failed_urls : '';
    }
}
