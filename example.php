<?php

/**
 * Cleantalk example
 *
 * @package Cleantalk Example
 * @copyright (C) 2011 - 2012 Сleantalk team (http://cleantalk.ru)
 * @license GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 * @see http://cleantalk.ru/wiki/doku.php/api
 *
*/

require_once (dirname(__FILE__) . '/cleantalk.class.php');

// Take params from config
$config_url = 'http://moderate.cleantalk.ru';
$auth_key = null; // Set Cleantalk auth key


// The facility in which to store the query parameters
$ct_request = new CleantalkRequest();

$ct_request->auth_key = $auth_key;
$ct_request->message = 'stop_word';
$ct_request->sender_email = 'stop_email@example.com';
$ct_request->sender_nickname = 'John Dow';
$ct_request->example = str_repeat('Just text ', 10);
$ct_request->agent = 'php-api';
$ct_request->sender_ip = '178.32.183.43';
$ct_request->js_on = 1; # Site visitor has JavaScript
$ct_request->submit_time = 12; # Seconds from start form filling till the form POST

$ct = new Cleantalk();
$ct->server_url = $config_url;

// Check
$ct_result = $ct->isAllowMessage($ct_request);

if ($ct_result->allow == 1) {
    echo 'Comment allowed. Reason ' . $ct_result->comment;
} else {
    echo 'Comment blocked. Reason ' . $ct_result->comment;
}

?>
