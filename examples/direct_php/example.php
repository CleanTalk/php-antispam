<?php

require_once "../../cleantalk-antispam.php";

/**
 * Cleantalk PHP example
 *
 * @package Cleantalk Example
 * @copyright (C) 2011 - 2025 CleanTalk team (https://cleantalk.org)
 * @license GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 * @see https://cleantalk.org/help/api-check-message
 *
 */

use Cleantalk\CleantalkRequest;
use Cleantalk\Cleantalk;
use Cleantalk\CleantalkAPI;

// Take params from config
$config_url = 'https://moderate.cleantalk.org';
$auth_key   = ''; // Set Cleantalk auth key

/**
 * Key validation example.
 */
$validation = CleantalkAPI::method__notice_validate_key($auth_key, 'php-api');
$validation = json_decode($validation) ? json_decode($validation) : false;
$is_valid = is_object($validation) && $validation->valid;

echo "Access key validation result:";
echo CleantalkAPI::method__notice_validate_key($auth_key, 'php-api');
echo "\n";

if (!$is_valid) {
    echo "Access key is not valid. Please check access key in the config.\n";
    exit;
}

// The facility in which to store the query parameters
$ct_request = new CleantalkRequest();

$ct_request->auth_key        = $auth_key;
$ct_request->message         = 'stop_word';
$ct_request->sender_email    = 'stop_email@example.com';
$ct_request->sender_nickname = 'John Dow';
$ct_request->example         = str_repeat('Just text ', 10);
$ct_request->agent           = 'php-api';
$ct_request->sender_ip       = '178.32.183.43';
$ct_request->event_token     = isset($_POST['ct_bot_detector_event_token']) ? $_POST['ct_bot_detector_event_token'] : null;

$ct             = new Cleantalk();
$ct->server_url = $config_url;

// Check
$ct_result = $ct->isAllowMessage($ct_request);

if ( $ct_result->allow == 1 ) {
    echo 'Comment allowed. Reason ' . $ct_result->comment;
} else {
    echo 'Comment blocked. Reason ' . $ct_result->comment;
}
