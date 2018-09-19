<?php
namespace lib;

/**
 * Cleantalk's API calls class
 * 
 * Mostly contains request's wrappers.
 *
 * @version 2.4
 * @package Cleantalk
 * @subpackage API
 * @author Cleantalk team (welcome@cleantalk.org)
 * @copyright (C) 2014 CleanTalk team (http://cleantalk.org)
 * @license GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 * @see https://github.com/CleanTalk/php-antispam 
 *
 */

class CleantalkAPI extends Cleantalk
{

	/**
	* Wrapper for sfw_logs API method
	* @param integer connect timeout
	* @return type
	* returns mixed STRING || array('error' => true, 'error_string' => STRING)
	*/
	static public function sfw_logs($api_key, $data, $do_check = true){
		
		$request = array(
			'auth_key' => $api_key,
			'method_name' => 'sfw_logs',
			'data' => json_encode($data),
			'rows' => count($data),
			'timestamp' => time()
		);
		$result = self::send_api_request($request);
		$result = $do_check ? self::filter_api_response($result, 'sfw_logs') : $result;
		
		return $result;
	}

	/*
	* Wrapper for 2s_blacklists_db API method
	* 
	* returns mixed STRING || array('error' => true, 'error_string' => STRING)
	*/
	static public function get_2s_blacklists_db($api_key, $do_check = true){
		
		$request = array(
			'agent' => APBCT_AGENT,
			'method_name' => '2s_blacklists_db',
			'auth_key' => $api_key,
		);
		
		$result = self::send_api_request($request);
		$result = $do_check ? self::filter_api_response($result, '2s_blacklists_db') : $result;
		
		return $result;
	}

	/**
	 * Function gets access key automatically
	 *
	 * @param string website admin email
	 * @param string website host
	 * @param string website platform
	 * @return type
	 */
	static public function get_api_key($email, $host, $platform, $timezone = null, $language = null, $ip = null, $do_check = true)
	{		
		$request = array(
			'method_name'          => 'get_api_key',
			'product_name'         => 'antispam',
			'agent'                => APBCT_AGENT,
			'email'                => $email,
			'website'              => $host,
			'platform'             => $platform,
			'timezone'             => $timezone,
			'http_accept_language' => !empty($_SERVER['HTTP_ACCEPT_LANGUAGE']) ? $_SERVER['HTTP_ACCEPT_LANGUAGE'] : null,
			'user_ip'              => $ip ? $ip : self::ip_get(array('real'), false),
		);
		
		$result = self::send_api_request($request);
		$result = $do_check ? self::filter_api_response($result, 'get_api_key') : $result;
		
		return $result;
	}
	
	/**
	 * Function gets information about renew notice
	 *
	 * @param string api_key
	 * @return type
	 */
	static public function notice_validate_key($api_key, $path_to_cms, $do_check = true)
	{
		$request = array(
			'agent' => APBCT_AGENT,
			'method_name' => 'notice_validate_key',
			'auth_key' => $api_key,
			'path_to_cms' => $path_to_cms	
		);
		
		$result = self::send_api_request($request);		    	
		$result = $do_check ? self::filter_api_response($result, 'notice_validate_key') : $result;

		return $result;
	}
	
	/**
	 * Function gets information about renew notice
	 *
	 * @param string api_key
	 * @return type
	 */
	static public function notice_paid_till($api_key, $do_check = true)
	{
		$request = array(
			'agent' => APBCT_AGENT,
			'method_name' => 'notice_paid_till',
			'auth_key' => $api_key
		);
		
		$result = self::send_api_request($request);
		$result = $do_check ? self::filter_api_response($result, 'notice_paid_till') : $result;
		
		return $result;
	}

	/**
	 * Function gets spam report
	 *
	 * @param string website host
	 * @param integer report days
	 * @return type
	 */
	static public function get_antispam_report($host, $period = 1)
	{
		$request=Array(
			'agent' => APBCT_AGENT,
			'method_name' => 'get_antispam_report',
			'hostname' => $host,
			'period' => $period
		);
		
		$result = self::send_api_request($request);
		// $result = $do_check ? self::filter_api_response($result, 'get_antispam_report') : $result;
		
		return $result;
	}
	
	/**
	 * Function gets spam statistics
	 *
	 * @param string website host
	 * @param integer report days
	 * @return type
	 */
	static public function get_antispam_report_breif($api_key, $do_check = true)
	{
		
		$request = array(
			'agent' => APBCT_AGENT,
			'method_name' => 'get_antispam_report_breif',
			'auth_key' => $api_key,
		);
		
		$result = self::send_api_request($request);
		$result = $do_check ? self::filter_api_response($result, 'get_antispam_report_breif') : $result;
		
		$tmp = array();
		for( $i = 0; $i < 7; $i++ )
			$tmp[ date( 'Y-m-d', time() - 86400 * 7 + 86400 * $i ) ] = 0;
		
		$result['spam_stat']    = array_merge( $tmp, isset($result['spam_stat']) ? $result['spam_stat'] : array() );
		$result['top5_spam_ip'] = isset($result['top5_spam_ip']) ? $result['top5_spam_ip'] : array();
		
		return $result;		
	}
	
	/**
	 * Function gets spam report
	 *
	 * @param string website host
	 * @param integer report days
	 * @return type
	 */
	static public function spam_check_cms($api_key, $data, $date = null, $do_check = true)
	{
		$request=Array(
			'agent' => APBCT_AGENT,
			'method_name' => 'spam_check_cms',
			'auth_key' => $api_key,
			'data' => is_array($data) ? implode(',',$data) : $data,
		);
		
		if($date) $request['date'] = $date;
		
		$result = self::send_api_request($request);
		$result = $do_check ? self::filter_api_response($result, 'spam_check_cms') : $result;
		
		return $result;
	}

    /**
     * Function checks server response
     *
     * @param string result
     * @param string request_method
     * @return mixed (array || array('error' => true))
     */
    static public function filter_api_response($result, $method_name = null)
    {   
        // Errors handling
        
        // Bad connection
        if(empty($result)){
            return array(
                'error' => true,
                'error_string' => 'CONNECTION_ERROR'
            );
        }
        
        // JSON decode errors
        $result = json_decode(json_encode($result), true);
        if(empty($result)){
            return array(
                'error' => true,
                'error_string' => 'JSON_DECODE_ERROR'
            );
        }
        
        // cURL error
        if(!empty($result['error'])){
            return array(
                'error' => true,
                'error_string' => 'CONNECTION_ERROR: ' . $result['error_string'],
            );
        }
        
        // Server errors
        if($result && (isset($result['error_no']) || isset($result['error_message']))){
            return array(
                'error' => true,
                'error_string' => "SERVER_ERROR NO: {$result['error_no']} MSG: {$result['error_message']}",
                'error_no' => $result['error_no'],
                'error_message' => $result['error_message']
            );
        }
        
        // Pathces for different methods
        
        // mehod_name = notice_validate_key
        if($method_name == 'notice_validate_key' && isset($result['valid'])){
            return $result;
        }
        
        // Other methods
        if(isset($result['data']) && is_array($result['data'])){
            return $result['data'];
        }
    }

    /**
     * Send JSON request to servers 
     * @param $msg
     * @return boolean|\CleantalkResponse
     */
    static public function send_api_request($data) {
    	return parent::sendRequest($data,'https://api.cleantalk.org', false);
    }    					
}