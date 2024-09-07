<?php

/* 
 * Patch for apache_request_headers() 
 * If Apache web server is missing then making
 */
if( !function_exists('apache_request_headers') ){
	function apache_request_headers(){
		
		$headers = array();	
		foreach($_SERVER as $key => $val){
			if(preg_match('/\AHTTP_/', $key)){
				$server_key = preg_replace('/\AHTTP_/', '', $key);
				$key_parts = explode('_', $server_key);
				if(count($key_parts) > 0 and strlen($server_key) > 2){
					foreach($key_parts as $part_index => $part){
						$key_parts[$part_index] = function_exists('mb_strtolower') ? mb_strtolower($part) : strtolower($part);
						$key_parts[$part_index][0] = strtoupper($key_parts[$part_index][0]);					
					}
					$server_key = implode('-', $key_parts);
				}
				$headers[$server_key] = $val;
			}
		}
		return $headers;
	}
}

/*
 * Patch for locale_get_display_region()
 * For old PHP versions
 */
if( !function_exists('locale_get_display_region') ){
	function locale_get_display_region($locale, $in_locale = 'EN'){
		
		return 'Unkonwn' . ($locale ? ': ' . $locale : '');
	}
}
