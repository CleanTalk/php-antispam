<?php
require_once 'lib/Cleantalk.php';
require_once 'lib/CleantalkRequest.php';
require_once 'lib/CleantalkResponse.php';

use lib\Cleantalk;
use lib\CleantalkRequest;
use lib\CleantalkResponse;

define ('CLEANTALK_TEST_API_KEY', 'ejujapepugu2');

class CleantalkTest extends \PHPUnit\Framework\TestCase 
{
	protected $ct;

	protected $ct_request;

	public function setUp()
	{
		$this->ct = new Cleantalk();
		$this->ct->server_url = 'http://moderate.cleantalk.org';
		$this->ct_request = new CleantalkRequest();
		$this->ct_request->auth_key = CLEANTALK_TEST_API_KEY;
	}

	public function testIsAllowMessage()
	{
		$this->ct_request->sender_email = 'good@mail.org';
		$this->ct_request->message = 'good message';
		$result = $this->ct->isAllowMessage($this->ct_request);
		$this->assertEquals(1, $result->allow);
		$this->assertEquals(0, $result->stop_queue);

		$this->ct_request->sender_email = 'good@mail.org';
		$this->ct_request->message = 'stop_word bad message';
		$result = $this->ct->isAllowMessage($this->ct_request);
		$this->assertEquals(0, $result->allow);	
		$this->assertEquals(0, $result->stop_queue);

		$this->ct_request->sender_email = 's@cleantalk.org';
		$this->ct_request->message = 'good message';
		$result = $this->ct->isAllowMessage($this->ct_request);
		$this->assertEquals(0, $result->allow);	
		$this->assertEquals(1, $result->stop_queue);

		$this->ct_request->sender_email = 's@cleantalk.org';
		$this->ct_request->message = 'stop_word bad message';
		$result = $this->ct->isAllowMessage($this->ct_request);
		$this->assertEquals(0, $result->allow);		
		$this->assertEquals(1, $result->stop_queue);			

	}
	
}