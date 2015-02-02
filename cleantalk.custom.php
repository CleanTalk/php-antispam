<?php
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

    $data = array(
        'auth_key' => '__CT_KEY__',
        'method_name' => 'check_newuser',
        'agent' => 'php-1.1',
        'sender_ip' => ct_session_ip($_SERVER['REMOTE_ADDR']),
        'sender_email' => $sender_email,
        'js_on' => $ct_checkjs,
        'submit_time' => $ct_submit_time,
        'sender_info' => null,
    );

    $result = ct_send_request($data, $ct_server_url);

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


/**
 * Send JSON request to servers 
 * @param $msg
 * @return boolean|\CleantalkResponse
 */
function ct_send_request($data = null, $url, $server_timeout = 3) {
    // Convert to array
    $data = json_decode(json_encode($data), true);

    // Convert to JSON
    $data = json_encode($data);
    
    $result = false;
    $curl_error = null;
    if(function_exists('curl_init')) {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_TIMEOUT, $server_timeout);
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
        // receive server response ...
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        // resolve 'Expect: 100-continue' issue
        curl_setopt($ch, CURLOPT_HTTPHEADER, array('Expect:'));
        
        $result = curl_exec($ch);
        if (!$result) {
            $curl_error = curl_error($ch);
        }
        
        curl_close($ch); 
    }

    if (!$result) {
        $allow_url_fopen = ini_get('allow_url_fopen');
        if (function_exists('file_get_contents') && isset($allow_url_fopen) && $allow_url_fopen == '1') {
            $opts = array('http' =>
              array(
                'method'  => 'POST',
                'header'  => "Content-Type: text/html\r\n",
                'content' => $data,
                'timeout' => $server_timeout
              )
            );

            $context  = stream_context_create($opts);
            $result = @file_get_contents($url, false, $context);
        }
    }

    if (!$result) {
        $response = null;
        $response['errno'] = 1;
        if ($curl_error) {
            $response['errstr'] = sprintf("CURL error: '%s'", $curl_error); 
        } else {
            $response['errstr'] = 'No CURL support compiled in'; 
        }
        $response['errstr'] .= ' or disabled allow_url_fopen in php.ini.'; 
        $response = json_decode(json_encode($response));
        
        return $response;
    }
    
    $errstr = null;
    $response = json_decode($result);
    if ($result !== false && is_object($response)) {
        $response->errno = 0;
        $response->errstr = $errstr;
    } else {
        $errstr = 'Unknown response from ' . $url . '.' . ' ' . $result;
        
        $response = null;
        $response['errno'] = 1;
        $response['errstr'] = $errstr;
        $response = json_decode(json_encode($response));
    } 
    
    
    return $response;
}
/**
*   Get user IP behind proxy server
*/
function ct_session_ip( $data_ip ) {
    if (!$data_ip || !preg_match("/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/", $data_ip)) {
        return $data_ip;
    }
    if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        
        $forwarded_ip = explode(",", $_SERVER['HTTP_X_FORWARDED_FOR']);

        // Looking for first value in the list, it should be sender real IP address
        if (!preg_match("/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/", $forwarded_ip[0])) {
            return $data_ip;
        }

        $private_src_ip = false;
        $private_nets = array(
            '10.0.0.0/8',
            '127.0.0.0/8',
            '176.16.0.0/12',
            '192.168.0.0/16',
        );

        foreach ($private_nets as $v) {

            // Private IP found
            if ($private_src_ip) {
                continue;
            }
            
            if ($this->net_match($v, $data_ip)) {
                $private_src_ip = true;
            }
        }
        if ($private_src_ip) {
            // Taking first IP from the list HTTP_X_FORWARDED_FOR 
            $data_ip = $forwarded_ip[0]; 
        }
    }

    return $data_ip;
}
?>
