<?php
require_once "lib/Cleantalk.php";
require_once "lib/CleantalkRequest.php";
require_once "lib/CleantalkResponse.php";
require_once "lib/CleantalkHelper.php";
require_once "lib/CleantalkAPI.php";
require_once "lib/cleantalk-php-patch.php";

use lib\Cleantalk;
use lib\CleantalkRequest;

class CleantalkTest extends \PHPUnit\Framework\TestCase 
{
	protected $ct;

	protected $ct_request;

	public function setUp()
	{
		$this->ct = new Cleantalk();
		$this->ct->server_url = 'http://moderate.cleantalk.org';
		$this->ct_request = new CleantalkRequest();
		$this->ct_request->auth_key = getenv("CLEANTALK_TEST_API_KEY");
	}

	public function testIsAllowMessage()
	{
		$this->ct_request->sender_email = 's@cleantalk.org';
		$this->ct_request->message = 'stop_word bad message';
		$result = $this->ct->isAllowMessage($this->ct_request);
		$this->assertEquals(0, $result->allow);					

		$this->ct_request->message = '';
		$this->ct_request->sender_email = '';
	}

	public function testIsAllowUser()
	{
		$this->ct_request->sender_email = 's@cleantalk.org';
		$result = $this->ct->isAllowUser($this->ct_request);
		$this->assertEquals(0, $result->allow);

		$this->ct_request->sender_email = '';
	}	
}