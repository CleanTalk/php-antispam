<?php
//require_once "vendor/autoload.php"; -- Composer

require_once "lib/Cleantalk.php";
require_once "lib/CleantalkRequest.php";
require_once "lib/CleantalkResponse.php";
require_once "lib/CleantalkHelper.php";
require_once "lib/CleantalkAPI.php";
require_once "lib/cleantalk-php-patch.php";

/**
 * Cleantalk example
 *
 * @package Cleantalk Example
 * @copyright (C) 2011 - 2012 Сleantalk team (https://cleantalk.org)
 * @license GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 * @see https://cleantalk.org/wiki/doku.php/api
 *
*/

use Cleantalk\CleantalkRequest;
use Cleantalk\Cleantalk;
use Cleantalk\CleantalkAPI;

// Take params from config
$config_url = 'https://moderate.cleantalk.org';
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
$ct_request->event_token = isset($_POST['ct_bot_detector_event_token']) ? $_POST['ct_bot_detector_event_token'] : null;

$ct = new Cleantalk();
$ct->server_url = $config_url;

// Check
$ct_result = $ct->isAllowMessage($ct_request);

if ($ct_result->allow == 1) {
    echo 'Comment allowed. Reason ' . $ct_result->comment;
} else {
    echo 'Comment blocked. Reason ' . $ct_result->comment;
}
echo "<br/>CleantalkAPI call example:<br/>";
var_dump(CleantalkAPI::method__notice_validate_key('',''));
?>
