<?php
require_once (dirname(__FILE__) . 'autoload.php');

/**
 * CleanTalk anti-spam script for any web form 
 *
 * @version 1.1
 * @package CleanTalk
 * @subpackage Base
 * @author СleanTalk team (welcome@cleantalk.org)
 * @copyright (C) 2014 СleanTalk team (http://cleantalk.org)
 * @license GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 * @see https://github.com/CleanTalk/php-antispam 
 *
 */
use lib\CleantalkRequest;
use lib\Cleantalk;
use lib\CleantalkHelper;
/*
    CleanTalk's global vars
*/
$ct_server_url = 'http://moderate.cleantalk.org/api2.0/';
$ct_pagetime_label = 'ct_pagetime';
$ct_checkjs_label = 'ct_checkjs';

ct_init();

/**
 * Starts CleanTalk 
 * @param null 
 * @return boolean|null
 */
function ct_init() {
    global $ct_pagetime_label, $ct_checkjs_label;
    
    if(session_id() === '') {
        @session_start();
    }

    if ($_SERVER['REQUEST_METHOD'] == 'POST') {
        ct_process_submission();
    } else {
        $_SESSION[$ct_pagetime_label] = time();
		$html = sprintf('
<script type="text/javascript">
function ctSetCookie() {
    var date = new Date();
    document.cookie = "%s=" + date.getFullYear() + "; path=/";
}
ctSetCookie();
</script>
',
            $ct_checkjs_label
        );      
        $html = str_replace(array("\n","\r"),'', $html);
        echo $html;
    }
    
    return null;
}

/**
 * Catchs and preapres POST data 
 * @param null 
 * @return boolean|null
 */
function ct_process_submission() {
    global $ct_pagetime_label, $ct_server_url, $ct_checkjs_label;
    
    $ct_checkjs = null;
    if (isset($_COOKIE[$ct_checkjs_label]) && $_COOKIE[$ct_checkjs_label] == date("Y")) {
        if ($_COOKIE[$ct_checkjs_label] == date("Y")) {
            $ct_checkjs = 1;
        } else {
            $ct_checkjs = 0;
        }
    }

    $ct_submit_time = null;
    if (isset($_SESSION[$ct_pagetime_label])) {
        $ct_submit_time = time() - $_SESSION[$ct_pagetime_label];
    }
   
    $sender_email = null;
    if (is_array($_POST)) {
        foreach ($_POST as $k => $v) {
            if ($sender_email === null && isset($v)) {
                if (is_string($v) && preg_match("/^\S+@\S+\.\S+$/", $v)) {
                    $sender_email = $v;
                }

                // Looking email address in arrays
                if (is_array($v)) {
                    foreach ($v as $v2) {
                        if ($sender_email) {
                            continue;
                        }
                        
                        if (is_string($v2) && preg_match("/^\S+@\S+\.\S+$/", $v2)) {
                            $sender_email = $v2;
                        }
                    }
                }
            }
        }
    }
    // Take params from config
    $config_url = 'http://moderate.cleantalk.ru';
    $auth_key = null; // Set Cleantalk auth key


    // The facility in which to store the query parameters
    $ct_request = new CleantalkRequest();

    $ct_request->auth_key = $auth_key;
    $ct_request->sender_email = $sender_email;
    $ct_request->agent = 'php-api';
    $ct_request->sender_ip = CleantalkHelper::ip_get(array('real'), false);
    $ct_request->js_on = $ct_checkjs; # Site visitor has JavaScript
    $ct_request->submit_time = $ct_submit_time; # Seconds from start form filling till the form POST

    $ct = new Cleantalk();
    $ct->server_url = $config_url;

    // Check
    $ct_result = $ct->isAllowUser($ct_request);

    if ($result->errno != 0) {
        error_log($result->errstr);
        return false;
    }
    
    if ($result->allow == 0 && isset($result->comment)) {
        $message = sprintf("<br /><br /><br /><center><span>%s</span></center>", $result->comment);
        echo $message;
        exit;
    }
    
    return null;
}
