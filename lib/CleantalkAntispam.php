<?php

namespace Cleantalk;

class CleantalkAntispam
{
	private $apikey;
	private $email_field;
	private $user_name_field;
	private $message_field;
	private $type_form;

	public function __construct(
		$apikey,
		$email_field,
		$user_name_field = '',
		$message_field = '',
		$type_form = 'contact'
	)
	{
		$this->apikey = $apikey;
		$this->email_field = $email_field;
		$this->user_name_field = $user_name_field;
		$this->message_field = $message_field;
		$this->type_form = $type_form;
	}

	public function handle()
	{
		if (count($_POST) === 0) {
			$_SESSION['ct_submit_time'] = time();
			return;
		}

		$sender_email = isset($_POST[$this->email_field]) ? $_POST[$this->email_field] : '';
		$sender_nickname = isset($_POST[$this->user_name_field]) ? $_POST[$this->user_name_field] : '';
		$message = isset($_POST[$this->message_field]) ? $_POST[$this->message_field] : '';
		$sender_ip = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : null;

		$ct_request = new CleantalkRequest();

		$ct_request->auth_key = $this->apikey;
		$ct_request->agent = 'php-api';
		$ct_request->sender_email = $sender_email;
		$ct_request->sender_ip = $sender_ip;
		$ct_request->sender_nickname = $sender_nickname;
		$ct_request->message = $message;
		$ct_request->submit_time = time() - (int) $_SESSION['ct_submit_time'];
		$ct_request->event_token = isset($_POST['ct_bot_detector_event_token']) ? $_POST['ct_bot_detector_event_token'] : null;

		$ct = new Cleantalk();
		$ct->server_url = $ct_request::CLEANTALK_API_URL;

		// Check
		if ($this->type_form === 'signup') {
			$ct_result = $ct->isAllowUser($ct_request);
		}
		if ($this->type_form === 'contact') {
			$ct_result = $ct->isAllowMessage($ct_request);
		}

        return $ct_result;
	}

	public function frontendScript()
	{
		echo '<script type="text/javascript" src="https://moderate.cleantalk.org/ct-bot-detector-wrapper.js"></script>';
	}
}