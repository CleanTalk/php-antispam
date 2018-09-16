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

	public function testSendFeedback()
	{
		$this->ct_request->feedback = '0:php-api';
		$result = $this->ct->sendFeedback($this->ct_request);
		$this->assertEquals('Ok.', $result->comment);
	}

	public function testFilterRequest()
	{
		$this->ct_request->sender_email = 0;
		$this->ct_request->sender_ip = 0;
		$this->ct_request->submit_time = 'value';
		$this->ct_request->js_on = false;
		$result = $this->ct->filterRequest($this->ct_request);
		$this->assertEquals(null, $result->sender_email);
		$this->assertEquals(null, $result->sender_ip);
		$this->assertEquals(null, $result->submit_time);
		$this->assertEquals(null, $result->js_on);
	}

	public function testCompressData()
	{
		$data = $this->ct->compressData('Cleantalk');
		$this->assertTrue(preg_match('%^[a-zA-Z0-9/+]*={0,2}$%', $data) ? true : false);
	}

	
}