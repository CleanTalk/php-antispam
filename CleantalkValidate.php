<?php
//require_once "vendor/autoload.php"; -- Composer

require_once "lib/Cleantalk.php";
require_once "lib/CleantalkRequest.php";
require_once "lib/CleantalkResponse.php";
require_once "lib/CleantalkHelper.php";

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
session_start();

if (!count($_POST))
    $_SESSION['ct_submit_time'] = time();

class CleantalkValidate 
{
    public static $server_url = 'https://moderate.cleantalk.org';
    public static $access_key = 'your access key';

    public static function spamCheckUser($name = '', $email = '') 
    { 
        $ct_request = new lib\CleantalkRequest(); 
        $ct_request->auth_key = self::$access_key; 
        $ct_request->agent = 'php-api'; 
        $ct_request->sender_email = $email; 
        $ct_request->sender_ip = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : null;
        $ct_request->sender_nickname = $name; 
        $ct_request->submit_time = time() - (int) $_SESSION['ct_submit_time'];
        $ct_request->js_on = 1; 
        $ct = new lib\Cleantalk(); 
        $ct->server_url = self::$server_url; 
        // Check 
        $ct_result = $ct->isAllowUser($ct_request); 

        return $ct_result;   
    } 
    public static function spamCheckMessage($name = '', $email = '', $message = '') 
    { 
        $ct_request = new CleantalkRequest(); 
        $ct_request->auth_key = self::$access_key; 
        $ct_request->agent = 'php-api'; 
        $ct_request->sender_email = $email; 
        $ct_request->sender_ip = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : null;
        $ct_request->sender_nickname = $name; 
        $ct_request->submit_time = time() - (int) $_SESSION['ct_submit_time'];
        $ct_request->message = $message; 
        $ct_request->js_on = 1; 
        $ct = new Cleantalk(); 
        $ct->server_url = self::$server_url; 
        // Check 
        $ct_result = $ct->isAllowMessage($ct_request); 

        return $ct_result; 
    }    
}

