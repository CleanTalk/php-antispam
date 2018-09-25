<?php

/*
 * CleanTalk database class
 * Version 1.0
 * author Cleantalk team (welcome@cleantalk.org)
 * copyright (C) 2014 CleanTalk team (http://cleantalk.org)
 * license GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 * see https://github.com/CleanTalk/php-antispam
*/

class CleantalkDB
{	
	
	public $table_prefix = '';
	public $result = array();
	
	private $db;
	private $query;
	private $db_result;
	
	/**
	* Creates connection to database
	* 
	* @param array $params
	*   array((string)'hostname', (string)'db_name', (string)'charset', (array)PDO options)
	* @param string $username
	* @param string $password
	*
	* @return void
	*/
	public function __construct($params, $username, $password)
	{
		$hostname        = !empty($params['hostname']) ? $params['hostname'] : 'localhost';
		$db_name         = !empty($params['db_name'])  ? $params['db_name']  : 'mysite';
		$charset         = !empty($params['charset'])  ? $params['charset']  : 'utf8';
		$request_options = !empty($params['options'])  ? $params['options']
			: array(
				PDO::ATTR_ERRMODE            => PDO::ERRMODE_SILENT,
				PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
			);
		$request = "mysql:host=$hostname;dbname=$db_name;charset=$charset";
		
		$this->db = PDO::__construct($request, $username, $password, $request_options);
	}
	
	public function query($query, $straight_query = false)
	{
		$this->db_result = $this->db->query($query);
		return $this->db_result;
	}
	
	public function fetch()
	{
		$this->result = $this->db_result->fetch();
	}
	
	public function fetch_all()
	{
		$this->result = $this->db_result->fetchAll();
	}
}
