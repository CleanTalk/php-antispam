<?php
namespace lib;

/**
 * Cleantalk Base class
 *
 * @version 2.3
 * @package Cleantalk
 * @subpackage Base
 * @author Cleantalk team (welcome@cleantalk.org)
 * @copyright (C) 2014 CleanTalk team (http://cleantalk.org)
 * @license GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 * @see https://github.com/CleanTalk/php-antispam 
 *
 */

class Cleantalk
{

    /**
     * Debug level
     * @var int
     */
    public $debug = 0;
    
    /**
    * Maximum data size in bytes
    * @var int
    */
    private $dataMaxSise = 32768;
    
    /**
    * Data compression rate 
    * @var int
    */
    private $compressRate = 6;
    
    /**
    * Server connection timeout in seconds 
    * @var int
    */
    private $server_timeout = 15;

    /**
     * Cleantalk server url
     * @var string
     */
    public $server_url = null;

    /**
     * Last work url
     * @var string
     */
    public $work_url = null;

    /**
     * WOrk url ttl
     * @var int
     */
    public $server_ttl = null;

    /**
     * Time wotk_url changer
     * @var int
     */
    public $server_changed = null;

    /**
     * Flag is change server url
     * @var bool
     */
    public $server_change = false;

    /**
     * Use TRUE when need stay on server. Example: send feedback
     * @var bool
     */
    public $stay_on_server = false;
    
    /**
     * Codepage of the data 
     * @var bool
     */
    public $data_codepage = null;
    
    /**
     * Use https connection to servers 
     * @var bool 
     */
    public $ssl_on = false;
    
    /**
     * Path to SSL certificate 
     * @var string
     */
    public $ssl_path = '';

    /**
     * Minimal server response in miliseconds to catch the server
     *
     */
    public $min_server_timeout = 50;

    /**
     * CDN IP's pool
     *
     */
    private $cdn_pool = array(
        'cloud_flare' => array(
            'ipv4' => array(
                '103.21.244.0/22',
                '103.22.200.0/22',
                '103.31.4.0/22',
                '104.16.0.0/12',
                '108.162.192.0/18',
                '131.0.72.0/22',
                '141.101.64.0/18',
                '162.158.0.0/15',
                '172.64.0.0/13',
                '173.245.48.0/20',
                '185.93.231.18/20', // User fix
                '185.220.101.46/20', // User fix
                '188.114.96.0/20',
                '190.93.240.0/20',
                '197.234.240.0/22',
                '198.41.128.0/17',
            ),
            'ipv6' => array(
                '2400:cb00::/32',
                '2405:8100::/32',
                '2405:b500::/32',
                '2606:4700::/32',
                '2803:f800::/32',
                '2c0f:f248::/32',
                '2a06:98c0::/29',
            ),
        ),
    );

    /**
     * Private networks IP's pool
     *
     */    
    private $private_networks = array(
        '10.0.0.0/8',
        '100.64.0.0/10',
        '172.16.0.0/12',
        '192.168.0.0/16',
        '127.0.0.1/32',
    ); 

    /**
     * Function checks whether it is possible to publish the message
     * @param CleantalkRequest $request
     * @return type
     */
    public function isAllowMessage(CleantalkRequest $request) {
        $request = $this->filterRequest($request);
        $msg = $this->createMsg('check_message', $request);
        return $this->httpRequest($msg);
    }

    /**
     * Function checks whether it is possible to publish the message
     * @param CleantalkRequest $request
     * @return type
     */
    public function isAllowUser(CleantalkRequest $request) {
        $request = $this->filterRequest($request);
        $msg = $this->createMsg('check_newuser', $request);
        return $this->httpRequest($msg);
    }

    /**
     * Function sends the results of manual moderation
     *
     * @param CleantalkRequest $request
     * @return type
     */
    public function sendFeedback(CleantalkRequest $request) {
        $request = $this->filterRequest($request);
        $msg = $this->createMsg('send_feedback', $request);
        return $this->httpRequest($msg);
    }

    /**
     *  Filter request params
     * @param CleantalkRequest $request
     * @return type
     */
    private function filterRequest(CleantalkRequest $request) {
        // general and optional
        foreach ($request as $param => $value) {
            if (in_array($param, array('message', 'example', 'agent',
                        'sender_info', 'sender_nickname', 'post_info', 'phone')) && !empty($value)) {
                if (!is_string($value) && !is_integer($value)) {
                    $request->$param = NULL;
                }
            }

            if (in_array($param, array('stoplist_check', 'allow_links')) && !empty($value)) {
                if (!in_array($value, array(1, 2))) {
                    $request->$param = NULL;
                }
            }
            
            if (in_array($param, array('js_on')) && !empty($value)) {
                if (!is_integer($value)) {
                    $request->$param = NULL;
                }
            }

            if ($param == 'sender_ip' && !empty($value)) {
                if (!is_string($value)) {
                    $request->$param = NULL;
                }
            }

            if ($param == 'sender_email' && !empty($value)) {
                if (!is_string($value)) {
                    $request->$param = NULL;
                }
            }

            if ($param == 'submit_time' && !empty($value)) {
                if (!is_int($value)) {
                    $request->$param = NULL;
                }
            }
        }
        return $request;
    }
    
    /**
     * Compress data and encode to base64 
     * @param type string
     * @return string 
     */
    private function compressData($data = null){
        
        if (strlen($data) > $this->dataMaxSise && function_exists('gzencode') && function_exists('base64_encode')){

            $localData = gzencode($data, $this->compressRate, FORCE_GZIP);

            if ($localData === false)
                return $data;
            
            $localData = base64_encode($localData);
            
            if ($localData === false)
                return $data;
            
            return $localData;
        }

        return $data;
    } 

    /**
     * Create msg for cleantalk server
     * @param type $method
     * @param CleantalkRequest $request
     * @return \xmlrpcmsg
     */
    private function createMsg($method, CleantalkRequest $request) {
        switch ($method) {
            case 'check_message':
                // Convert strings to UTF8
                $request->message = $this->stringToUTF8($request->message, $this->data_codepage);
                $request->example = $this->stringToUTF8($request->example, $this->data_codepage);
                $request->sender_email = $this->stringToUTF8($request->sender_email, $this->data_codepage);
                $request->sender_nickname = $this->stringToUTF8($request->sender_nickname, $this->data_codepage);

                $request->message = $this->compressData($request->message);
                $request->example = $this->compressData($request->example);
                break;

            case 'check_newuser':
                // Convert strings to UTF8
                $request->sender_email = $this->stringToUTF8($request->sender_email, $this->data_codepage);
                $request->sender_nickname = $this->stringToUTF8($request->sender_nickname, $this->data_codepage);
                break;

            case 'send_feedback':
                if (is_array($request->feedback)) {
                    $request->feedback = implode(';', $request->feedback);
                }
                break;
        }
        
        $request->method_name = $method;
        
        //
        // Removing non UTF8 characters from request, because non UTF8 or malformed characters break json_encode().
        //
        foreach ($request as $param => $value) {
            if (!preg_match('//u', $value))
                $request->{$param} = 'Nulled. Not UTF8 encoded or malformed.'; 
        }
        
        return $request;
    }
    
    /**
     * Send JSON request to servers 
     * @param $msg
     * @return boolean|\CleantalkResponse
     */
    protected static function sendRequest($data = null, $url, $moderate = true, $server_timeout = 3) {
        // Convert to array
        $data = (array)json_decode(json_encode($data), true);
        
        $original_url = $url;
        $original_data = $data;
        
        //Cleaning from 'null' values
        $tmp_data = array();
        foreach($data as $key => $value){
            if($value !== null){
                $tmp_data[$key] = $value;
            }
        }
        $data = $tmp_data;
        unset($key, $value, $tmp_data);
        
        if ($moderate){
            $url = $url . '/api2.0'; 
            $data = json_encode($data);            
        }
        else
        {
            $data = http_build_query($data);
            $data = str_replace("&amp;", "&", $data);
        }
        
        $result = false;
        $curl_error = null;
        if(function_exists('curl_init')){
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $url);
            curl_setopt($ch, CURLOPT_TIMEOUT, $server_timeout);
            curl_setopt($ch, CURLOPT_POST, 1);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
            // receive server response ...
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            // resolve 'Expect: 100-continue' issue
            curl_setopt($ch, CURLOPT_HTTPHEADER, array('Expect:'));
            // see http://stackoverflow.com/a/23322368
            curl_setopt($ch, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_0);
            
            // Disabling CA cert verivication
            // Disabling common name verification
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
            
            $result = curl_exec($ch);
            if (!$result)
                $curl_error = curl_error($ch);
            
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
     * httpRequest 
     * @param $msg
     * @return boolean|\CleantalkResponse
     */
    private function httpRequest($msg) {
        
        $result = false;
        
        if($msg->method_name != 'send_feedback'){
            $tmp = function_exists('apache_request_headers')
                ? apache_request_headers()
                : $this->apache_request_headers();
            
            if(isset($tmp['Cookie'])){
                $cookie_name = 'Cookie';
            }elseif(isset($tmp['cookie'])){
                $cookie_name = 'cookie';
            }else{
                $cookie_name = 'COOKIE';
            }
            
            if(isset($tmp[$cookie_name])){
                $tmp[$cookie_name] = preg_replace(array(
                    '/\s{0,1}ct_checkjs=[a-z0-9]*[;|$]{0,1}/',
                    '/\s{0,1}ct_timezone=.{0,1}\d{1,2}[;|$]/', 
                    '/\s{0,1}ct_pointer_data=.*5D[;|$]{0,1}/', 
                    '/;{0,1}\s{0,3}$/'
                ), '', $tmp[$cookie_name]);
            }
            
            $msg->all_headers=json_encode($tmp);
        }
        
        $si=(array)json_decode($msg->sender_info,true);

        $msg->sender_ip = $this->ip_get(array('real'), false);
        $msg->x_forwarded_for = $this->ip_get(array('x_forwarded_for'), false);
        $msg->x_real_ip = $this->ip_get(array('x_real_ip'), false);

        $msg->sender_info=json_encode($si);
        if (((isset($this->work_url) && $this->work_url !== '') && ($this->server_changed + $this->server_ttl > time()))
                || $this->stay_on_server == true) {
            
            $url = (!empty($this->work_url)) ? $this->work_url : $this->server_url;
                    
            $result = $this->sendRequest($msg, $url, $this->server_timeout);
        }

        if (($result === false || $result->errno != 0) && $this->stay_on_server == false) {
            // Split server url to parts
            preg_match("@^(https?://)([^/:]+)(.*)@i", $this->server_url, $matches);
            $url_prefix = '';
            if (isset($matches[1]))
                $url_prefix = $matches[1];

            $pool = null;
            if (isset($matches[2]))
                $pool = $matches[2];
            
            $url_suffix = '';
            if (isset($matches[3]))
                $url_suffix = $matches[3];
            
            if ($url_prefix === '')
                $url_prefix = 'http://';

            if (empty($pool)) {
                return false;
            } else {
                // Loop until find work server
                foreach ($this->get_servers_ip($pool) as $server) {
                    if ($server['host'] === 'localhost' || $server['ip'] === null) {
                        $work_url = $server['host'];
                    } else {
                        $server_host = $server['ip'];
                        $work_url = $server_host;
                    }
                    $host = filter_var($work_url,FILTER_VALIDATE_IP) ? gethostbyaddr($work_url) : $work_url;
                    $work_url = $url_prefix . $host; 
                    if (isset($url_suffix)) 
                        $work_url = $work_url . $url_suffix;
                    
                    $this->work_url = $work_url;
                    $this->server_ttl = $server['ttl'];
                    
                    $result = $this->sendRequest($msg, $this->work_url, $this->server_timeout);

                    if ($result !== false && $result->errno === 0) {
                        $this->server_change = true;
                        break;
                    }
                }
            }
        }
        
        $response = new CleantalkResponse(null, $result);
        
        if (!empty($this->data_codepage) && $this->data_codepage !== 'UTF-8') 
        {
            if (!empty($response->comment))
            $response->comment = $this->stringFromUTF8($response->comment, $this->data_codepage);
            if (!empty($response->errstr))
            $response->errstr = $this->stringFromUTF8($response->errstr, $this->data_codepage);
            if (!empty($response->sms_error_text))
            $response->sms_error_text = $this->stringFromUTF8($response->sms_error_text, $this->data_codepage);
        }
        
        return $response;
    }
    
    /**
     * Function DNS request
     * @param $host
     * @return array
     */
    private function get_servers_ip($host)
    {
        $response = null;
        if (!isset($host))
            return $response;

        if (function_exists('dns_get_record')) {
            $records = @dns_get_record($host, DNS_A);

            if ($records !== FALSE) {
                foreach ($records as $server) {
                    $response[] = $server;
                }
            }
        }

        if (count($response) == 0 && function_exists('gethostbynamel')) {
            $records = gethostbynamel($host);

            if ($records !== FALSE) {
                foreach ($records as $server) {
                    $response[] = array(
                        "ip" => $server,
                        "host" => $host,
                        "ttl" => $this->server_ttl
                    );
                }
            }
        }

        if (count($response) == 0) {
            $response[] = array("ip" => null,
                "host" => $host,
                "ttl" => $this->server_ttl
            );
        } else {
            // $i - to resolve collisions with localhost
            $i = 0;
            $r_temp = null;
            $fast_server_found = false;
            foreach ($response as $server) {
                
                // Do not test servers because fast work server found
                if ($fast_server_found) {
                    $ping = $this->min_server_timeout; 
                } else {
                    $ping = $this->httpPing($server['ip']);
                    $ping = $ping * 1000;
                }
                
                // -1 server is down, skips not reachable server
                if ($ping != -1) {
                    $r_temp[$ping + $i] = $server;
                }
                $i++;
                
                if ($ping < $this->min_server_timeout) {
                    $fast_server_found = true;
                }
            }
            if (count($r_temp)){
                ksort($r_temp);
                $response = $r_temp;
            }
        }

        return $response;
    }
    
    /**
    * Function to check response time
    * param string
    * @return int
    */
    private function httpPing($host){

        // Skip localhost ping cause it raise error at fsockopen.
        // And return minimun value 
        if ($host == 'localhost')
            return 0.001;

        $starttime = microtime(true);
        $file      = @fsockopen ($host, 80, $errno, $errstr, $this->server_timeout);
        $stoptime  = microtime(true);
        $status    = 0;
        if (!$file) {
            $status = -1;  // Site is down
        } else {
            fclose($file);
            $status = ($stoptime - $starttime);
            $status = round($status, 4);
        }
        
        return $status;
    }
    
    /**
    * Function convert string to UTF8 and removes non UTF8 characters 
    * param string
    * param string
    * @return string
    */
    private function stringToUTF8($str, $data_codepage = null){
        if (!preg_match('//u', $str) && function_exists('mb_detect_encoding') && function_exists('mb_convert_encoding'))
        {
            
            if ($data_codepage !== null)
                return mb_convert_encoding($str, 'UTF-8', $data_codepage);

            $encoding = mb_detect_encoding($str);
            if ($encoding)
                return mb_convert_encoding($str, 'UTF-8', $encoding);
        }
        
        return $str;
    }
    
    /**
    * Function convert string from UTF8 
    * param string
    * param string
    * @return string
    */
    private function stringFromUTF8($str, $data_codepage = null){
        if (preg_match('//u', $str) && function_exists('mb_convert_encoding') && $data_codepage !== null)
        {
            return mb_convert_encoding($str, $data_codepage, 'UTF-8');
        }
        
        return $str;
    }

    /*
     * Check if the IP belong to mask. Recursivly if array given
     * @param ip string  
     * @param cird mixed (string|array of strings)
    */
    private function ip_mask_match($ip, $cidr){
        if(is_array($cidr)){
            foreach($cidr as $curr_mask){
                if($this->ip_mask_match($ip, $curr_mask)){
                    return true;
                }
            } unset($curr_mask);
            return false;
        }
        $exploded = explode ('/', $cidr);
        $net = $exploded[0];
        $mask = 4294967295 << (32 - $exploded[1]);
        return (ip2long($ip) & $mask) == (ip2long($net) & $mask);
    }

    /*
    *   Validating IPv4, IPv6
    *   param (string) $ip
    *   returns (string) 'v4' || (string) 'v6' || (bool) false
    */
    private function ip_validate($ip)
    {
        if(!$ip)                                                  return false; // NULL || FALSE || '' || so on...
        if(filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) return 'v4';  // IPv4
        if(filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) return 'v6';  // IPv6
                                                                  return false; // Unknown
    }

    /* 
     * If Apache web server is missing then making
     * Patch for apache_request_headers() 
     */
    private function apache_request_headers(){
        
        $headers = array(); 
        foreach($_SERVER as $key => $val){
            if(preg_match('/\AHTTP_/', $key)){
                $server_key = preg_replace('/\AHTTP_/', '', $key);
                $key_parts = explode('_', $server_key);
                if(count($key_parts) > 0 and strlen($server_key) > 2){
                    foreach($key_parts as $part_index => $part){
                        $key_parts[$part_index] = mb_strtolower($part);
                        $key_parts[$part_index][0] = strtoupper($key_parts[$part_index][0]);                    
                    }
                    $server_key = implode('-', $key_parts);
                }
                $headers[$server_key] = $val;
            }
        }
        return $headers;
    }

    private function cleantalk_is_JSON($string){
        return ((is_string($string) && (is_object(json_decode($string)) || is_array(json_decode($string))))) ? true : false;
    }
    /*
    *   Getting arrays of IP (REMOTE_ADDR, X-Forwarded-For, X-Real-Ip, Cf_Connecting_Ip)
    *   reutrns array('remote_addr' => 'val', ['x_forwarded_for' => 'val', ['x_real_ip' => 'val', ['cloud_flare' => 'val']]])
    */
    private function ip_get($ips_input = array('real', 'remote_addr', 'x_forwarded_for', 'x_real_ip', 'cloud_flare'), $v4_only = true)
    {
        $ips = array();
        foreach($ips_input as $ip_type){
            $ips[$ip_type] = '';
        } unset($ip_type);
                
        $headers = function_exists('apache_request_headers') ? apache_request_headers() : $this->apache_request_headers();
        
        // REMOTE_ADDR
        if(isset($ips['remote_addr'])){
            $ips['remote_addr'] = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '';
        }
        
        // X-Forwarded-For
        if(isset($ips['x_forwarded_for'])){
            if(isset($headers['X-Forwarded-For'])){
                $tmp = explode(",", trim($headers['X-Forwarded-For']));
                $ips['x_forwarded_for']= trim($tmp[0]);
            }
        }
        
        // X-Real-Ip
        if(isset($ips['x_real_ip'])){
            if(isset($headers['X-Real-Ip'])){
                $tmp = explode(",", trim($headers['X-Real-Ip']));
                $ips['x_real_ip']= trim($tmp[0]);
            }
        }
        
        // Cloud Flare
        if(isset($ips['cloud_flare'])){
            if(isset($headers['Cf-Connecting-Ip'])){
                if($this->ip_mask_match($ips['remote_addr'], $this->cdn_pool['cloud_flare']['ipv4'])){
                    $ips['cloud_flare'] = $headers['Cf-Connecting-Ip'];
                }
            }
        }
        
        // Getting real IP from REMOTE_ADDR or Cf_Connecting_Ip if set or from (X-Forwarded-For, X-Real-Ip) if REMOTE_ADDR is local.
        if(isset($ips['real'])){
            
            $ips['real'] = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '';
            
            // Cloud Flare
            if(isset($headers['Cf-Connecting-Ip'])){
                if($this->ip_mask_match($ips['real'], $this->cdn_pool['cloud_flare']['ipv4'])){
                    $ips['real'] = $headers['Cf-Connecting-Ip'];
                }
            // Incapsula proxy
            }elseif(isset($headers['Incap-Client-Ip'])){
                $ips['real'] = $headers['Incap-Client-Ip'];
            // Private networks. Looking for X-Forwarded-For and X-Real-Ip
            }elseif($this->ip_mask_match($ips['real'], $this->private_networks)){
                if(isset($headers['X-Forwarded-For'])){
                    $tmp = explode(",", trim($headers['X-Forwarded-For']));
                    $ips['real']= trim($tmp[0]);
                }elseif(isset($headers['X-Real-Ip'])){
                    $tmp = explode(",", trim($headers['X-Real-Ip']));
                    $ips['real']= trim($tmp[0]);
                }
            }
        }
        
        // Validating IPs
        $result = array();
        foreach($ips as $key => $ip){
            if($v4_only){
                if($this->ip_validate($ip) == 'v4')
                    $result[$key] = $ip;
            }else{
                if($this->ip_validate($ip))
                    $result[$key] = $ip;
            }
        }
        
        $result = array_unique($result);
        
        return count($ips_input) > 1 
            ? $result 
            : (reset($result) !== false
                ? reset($result)
                : null);
    }        
}
