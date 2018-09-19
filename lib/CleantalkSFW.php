<?php

/*
 * CleanTalk SpamFireWall base class
 * Compatible only with Wordpress.
 * @depends on CleantalkHelper class
 * Version 2.0-wp
 * author Cleantalk team (welcome@cleantalk.org)
 * copyright (C) 2014 CleanTalk team (http://cleantalk.org)
 * license GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 * see https://github.com/CleanTalk/php-antispam
*/

class CleantalkSFW
{
	public $ip = 0;
	public $ip_str = '';
	public $ip_array = Array();
	public $ip_str_array = Array();
	public $blocked_ip = '';
	public $passed_ip = '';
	public $result = false;
	
	//Database variables
	private $table_prefix;
	private $db;
	private $query;
	private $db_result;
	private $db_result_data = array();
	
	public function __construct()
	{
		$this->table_prefix = "";
		$this->db = $db;
	}
	
	public function unversal_query($query, $straight_query = false)
	{
		if($straight_query)
			$this->db_result = $this->db->query($query);
		else
			$this->query = $query;
	}
	
	public function unversal_fetch()
	{
		$this->db_result_data = $this->db->get_row($this->query, ARRAY_A);
	}
	
	public function unversal_fetch_all()
	{
		$this->db_result_data = $this->db->get_results($this->query, ARRAY_A);
	}
	
	/*
	*	Getting arrays of IP (REMOTE_ADDR, X-Forwarded-For, X-Real-Ip, Cf_Connecting_Ip)
	*	reutrns array('remote_addr' => 'val', ['x_forwarded_for' => 'val', ['x_real_ip' => 'val', ['cloud_flare' => 'val']]])
	*/
	static public function ip_get($ips_input = array('real', 'remote_addr', 'x_forwarded_for', 'x_real_ip', 'cloud_flare'), $v4_only = true){
		
		$result = (array)CleantalkHelper::ip_get($ips_input, $v4_only);
		
		$result = !empty($result) ? $result : array();
		
		if(isset($_GET['sfw_test_ip'])){
			if(CleantalkHelper::ip_validate($_GET['sfw_test_ip']) !== false)
				$result['sfw_test'] = $_GET['sfw_test_ip'];
		}
		
		return $result;
		
	}
	
	/*
	*	Checks IP via Database
	*/
	public function check_ip(){
		
		foreach($this->ip_array as $current_ip){
		
			$query = "SELECT 
				COUNT(network) AS cnt
				FROM ".$this->table_prefix."cleantalk_sfw
				WHERE network = ".sprintf("%u", ip2long($current_ip))." & mask;";
			$this->unversal_query($query);
			$this->unversal_fetch();
			
			if($this->db_result_data['cnt']){
				$this->result = true;
				$this->blocked_ip = $current_ip;
			}else{
				$this->passed_ip = $current_ip;
			}
		}
	}
		
	/*
	*	Add entry to SFW log
	*/
	public function sfw_update_logs($ip, $result){
		
		if($ip === NULL || $result === NULL){
			return;
		}
		
		$blocked = ($result == 'blocked' ? ' + 1' : '');
		$time = time();

		$query = "INSERT INTO ".$this->table_prefix."cleantalk_sfw_logs
		SET 
			ip = '$ip',
			all_entries = 1,
			blocked_entries = 1,
			entries_timestamp = '".intval($time)."'
		ON DUPLICATE KEY 
		UPDATE 
			all_entries = all_entries + 1,
			blocked_entries = blocked_entries".strval($blocked).",
			entries_timestamp = '".intval($time)."'";

		$this->unversal_query($query, true);
	}
	
	/*
	* Updates SFW local base
	* 
	* return mixed true || array('error' => true, 'error_string' => STRING)
	*/
	public function sfw_update($ct_key){
		
		$result = CleantalkAPI::api_method__get_2s_blacklists_db($ct_key);
		
		if(empty($result['error'])){
			
			$this->unversal_query("DELETE FROM ".$this->table_prefix."cleantalk_sfw;", true);
						
			// Cast result to int
			foreach($result as $value){
				$value[0] = intval($value[0]);
				$value[1] = intval($value[1]);
			} unset($value);
			
			$query="INSERT INTO ".$this->table_prefix."cleantalk_sfw VALUES ";
			for($i=0, $arr_count = count($result); $i < $arr_count; $i++){
				if($i == count($result)-1){
					$query.="(".$result[$i][0].",".$result[$i][1].");";
				}else{
					$query.="(".$result[$i][0].",".$result[$i][1]."), ";
				}
			}
			$this->unversal_query($query, true);
			
			return true;
			
		}else{
			return $result;
		}
	}
	
	/*
	* Sends and wipe SFW log
	* 
	* returns mixed true || array('error' => true, 'error_string' => STRING)
	*/
	public function send_logs($ct_key){
		
		//Getting logs
		$query = "SELECT * FROM ".$this->table_prefix."cleantalk_sfw_logs";
		$this->unversal_query($query);
		$this->unversal_fetch_all();
		
		if(count($this->db_result_data)){
			
			//Compile logs
			$data = array();
			foreach($this->db_result_data as $key => $value){
				$data[] = array(trim($value['ip']), $value['all_entries'], $value['all_entries']-$value['blocked_entries'], $value['entries_timestamp']);
			}
			unset($key, $value);
			
			//Sending the request
			$result = CleantalkAPI::api_method__sfw_logs($ct_key, $data);
			
			//Checking answer and deleting all lines from the table
			if(empty($result['error'])){
				if($result['rows'] == count($data)){
					$this->unversal_query("DELETE FROM ".$this->table_prefix."cleantalk_sfw_logs", true);
					return true;
				}
			}else{
				return $result;
			}
				
		}else{
			return array('error' => true, 'error_string' => 'NO_LOGS_TO_SEND');
		}
	}
	
	/*
	* Shows DIE page
	* 
	* Stops script executing
	*/	
	public function sfw_die($api_key, $cookie_prefix = '', $cookie_domain = ''){
		
		// File exists?
		if(file_exists(CLEANTALK_PLUGIN_DIR . "inc/sfw_die_page.html")){
			$sfw_die_page = file_get_contents(CLEANTALK_PLUGIN_DIR . "inc/sfw_die_page.html");
		}else{
			wp_die("IP BLACKLISTED", "Blacklisted", Array('response'=>403), true);
		}
		
		// Translation
		$request_uri = $_SERVER['REQUEST_URI'];
		$sfw_die_page = str_replace('{SFW_DIE_NOTICE_IP}',              __('SpamFireWall is activated for your IP ', 'cleantalk'), $sfw_die_page);
		$sfw_die_page = str_replace('{SFW_DIE_MAKE_SURE_JS_ENABLED}',   __('To continue working with web site, please make sure that you have enabled JavaScript.', 'cleantalk'), $sfw_die_page);
		$sfw_die_page = str_replace('{SFW_DIE_CLICK_TO_PASS}',          __('Please click below to pass protection,', 'cleantalk'), $sfw_die_page);
		$sfw_die_page = str_replace('{SFW_DIE_YOU_WILL_BE_REDIRECTED}', sprintf(__('Or you will be automatically redirected to the requested page after %d seconds.', 'cleantalk'), 1), $sfw_die_page);
		$sfw_die_page = str_replace('{CLEANTALK_TITLE}',                __('Antispam by CleanTalk', 'cleantalk'), $sfw_die_page);
		
		// Service info
		$sfw_die_page = str_replace('{REMOTE_ADDRESS}', $this->blocked_ip, $sfw_die_page);
		$sfw_die_page = str_replace('{REQUEST_URI}', $request_uri, $sfw_die_page);
		$sfw_die_page = str_replace('{COOKIE_PREFIX}', $cookie_prefix, $sfw_die_page);
		$sfw_die_page = str_replace('{COOKIE_DOMAIN}', $cookie_domain, $sfw_die_page);
		$sfw_die_page = str_replace('{SFW_COOKIE}', md5($this->blocked_ip.$api_key), $sfw_die_page);
		
		// Headers
		if(headers_sent() === false){
			header('Expires: '.date(DATE_RFC822, mktime(0, 0, 0, 1, 1, 1971)));
			header('Cache-Control: no-store, no-cache, must-revalidate');
			header('Cache-Control: post-check=0, pre-check=0', FALSE);
			header('Pragma: no-cache');
			header("HTTP/1.0 403 Forbidden");
			$sfw_die_page = str_replace('{GENERATED}', "", $sfw_die_page);
		}else{
			$sfw_die_page = str_replace('{GENERATED}', "<h2 class='second'>The page was generated at&nbsp;".date("D, d M Y H:i:s")."</h2>",$sfw_die_page);
		}
		
		wp_die($sfw_die_page, "Blacklisted", Array('response'=>403));
		
	}
}
