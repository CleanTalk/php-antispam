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

		$this->ct_request->sender_email = 's@cleantalk.org';
		$this->ct_request->message = 'stop_word bad message';
		$result = $this->ct->isAllowMessage($this->ct_request);
		$this->assertEquals(0, $result->allow);					

		$this->ct_request->message = '';
		$this->ct_request->sender_email = '';
	}

	public function testIsAllowUser()
	{
		$this->ct_request->sender_email = 'good@mail.org';
		$result = $this->ct->isAllowUser($this->ct_request);
		$this->assertEquals(1, $result->allow);

		$this->ct_request->sender_email = 's@cleantalk.org';
		$result = $this->ct->isAllowUser($this->ct_request);
		$this->assertEquals(0, $result->allow);

		$this->ct_request->sender_email = '';
	}

	public function testGetCleantalkCommentHash()
	{
		$result = $this->ct->getCleantalkCommentHash("*** Forbidden. Sender blacklisted. ***");
		$this->assertEquals(null, $result);
	}

	public function testAddCleantalkComment()
	{
		$result = $this->ct->addCleantalkComment("CT", "Forbidden. Sender blacklisted.");
		$this->assertEquals("CT\n\n*** Forbidden. Sender blacklisted. ***", $result);
	}

	public function testDelCleantalkComment()
	{
		$result = $this->ct->delCleantalkComment("CT\n\n*** Forbidden. Sender blacklisted. ***");
		$this->assertEquals("CT", $result);		
	}
	
}