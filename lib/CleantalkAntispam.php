<?php

namespace CleanTalk;

use CleanTalk\CleantalkVerdict;
use CleanTalk\HTTP\CleantalkResponse;
use CleanTalk\HTTP\Helper;
use CleanTalk\HTTP\Request;

class CleantalkAntispam
{
    const MODERATE_URL = 'https://moderate.cleantalk.org/api2.0';
    const BOT_DETECTOR_LIBRARY_URL = 'https://fd.cleantalk.org/ct-bot-detector-wrapper.js';
    const EVENT_TOKEN_FIELD_NAME = 'ct_bot_detector_event_token';
    const EMAIL_ADDRESS_REGEXP = '/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/';

    /**
     * @var string Access key for CleanTalk API
     */
    private $access_key;
    /**
     * @var string Is bot detector included
     */
    private $event_token_enabled;
    /**
     * @var string Event token for CleanTalk API
     */
    private $event_token;
    /**
     * @var bool
     */
    private $block_no_js_visitor = false;
    /**
     * @var string Nickname of the sender
     */
    private $nickname;
    /**
     * @var string Email of the sender
     */
    private $email;

    /**
     * @var string Message content
     */
    private $message;

    /**
     * @var string IP address of the sender
     */
    private $ip;

    /**
     * @var string Method name for the CleanTalk API request
     */
    private $method_name;

    /**
     * @var CleantalkVerdict Verdict object to store the result of the CleanTalk check
     */
    private $verdict;

    /**
     * @var array Suggestions for improving the data quality
     */
    private $improvement_suggestions  = array();

    /**
     * @var array Stack of method calls for fluid interface
     */
    private $fluid_call_stack = array();

    /**
     * @var CleantalkResponse Response object from the CleanTalk API
     */
    private $cleantalk_response;

    /**
     * @var false|string CleanTalk request data in JSON format
     */
    private $cleantalk_request_data;

    /**
     * @var array Data container to get the data from the form, usually is $_POST
     */
    private $data_container;

    /**
     * ------------ Construction kit methods ------------
     */

    /**
     * Constructor for the CleanTalkCheck class.
     *
     * @param string $accessKey Access key for CleanTalk API
     * @psalm-suppress PossiblyUnusedParam
     */
    public function __construct($accessKey, $email = '', $user_name_field = '', $message_field = '', $type_form = '')
    {
        $this->access_key = $accessKey;
        $this->verdict = new CleantalkVerdict();
        //default data preparing
        $this->data_container = $_POST;
        if (isset($this->data_container[static::EVENT_TOKEN_FIELD_NAME])) {
            $this->event_token = $this->data_container[static::EVENT_TOKEN_FIELD_NAME];
        }
        $this->ip = Helper::ipGet();
        if ($email) {
            $this->email = $email;
        } else {
            $this->setEmailAutomatically();
        }
    }

    private function setEmailAutomatically()
    {
        foreach ($this->data_container as $_key => $value) {
            if (preg_match(static::EMAIL_ADDRESS_REGEXP, $value)) {
                $this->email = $value;
                break;
            }
        }
    }

    /**
     * ------------ Frontend methods ------------
     */

    /**
     * Get the frontend HTML code for the CleanTalk bot detector.
     *
     * @param bool $warn_if_js_disabled Flag to include a warning if JavaScript is disabled
     * @return string HTML code
     */
    public static function getFrontendHTMLCode($warn_if_js_disabled = false)
    {
        $warn = $warn_if_js_disabled ? '<noscript><div>Please, enable JavaScript in the browser to process the form</div></noscript>' : '';
        $html = '<script src="%s"></script>%s';
        return sprintf($html, static::BOT_DETECTOR_LIBRARY_URL, $warn);
    }

    /**
     * ------------ Internal processing methods ------------
     */

    /**
     * Get the response from the CleanTalk API.
     *
     * @return CleantalkResponse Response object from the CleanTalk API
     */
    private function getCleanTalkResponse()
    {
        $http = new Request();
        $this->cleantalk_request_data = $this->prepareCleanTalkRequestData();
        $response_raw = $http->setUrl(static::MODERATE_URL)
                            ->setData($this->cleantalk_request_data)
                            ->request();

        /** @psalm-suppress InvalidArgument */
        return new CleantalkResponse(@json_decode($response_raw), null);
    }

    /**
     * Prepare the request data for the CleanTalk API.
     *
     * @return string JSON encoded request data
     */
    private function prepareCleanTalkRequestData()
    {
        $data = array(
            'method_name' => $this->method_name,
            'auth_key' => $this->access_key,
            'message' => $this->message,
            'sender_nickname' => $this->nickname,
            'sender_email' => $this->email,
            'sender_ip' => $this->ip,
            'js_on' => !empty($this->event_token) ? 1 : 0,
            'event_token' => $this->event_token,
            'agent' => 'php-cleantalk-check',
            'sender_info' => @json_encode(
                array(
                    'REFFERRER' => !empty($_SERVER['HTTP_REFERER']) ? $_SERVER['HTTP_REFERER'] : '',
                )
            ),
        );
        if ( isset($this->event_token_enabled) ) {
            $data['event_token_enabled'] = $this->event_token_enabled;
        }
        return @json_encode($data);
    }

    /**
     * Get the CleanTalk request data.
     *
     * @return string JSON encoded request data
     */
    public function getCleanTalkRequestData()
    {
        if (empty($this->cleantalk_request_data)) {
            return '';
        }
        $data = @json_decode($this->cleantalk_request_data);
        return $data ?: '';
    }

    /**
     * Verify the data before sending the request to CleanTalk API.
     */
    private function verifyData()
    {
        try {
            $this->checkAccessKey();
        } catch (\Exception $e) {
            $this->verdict->error = $e->getMessage();
            $this->verdict->allow = true;
        }

        try {
            $this->checkEventToken();
        } catch (\Exception $e) {
            if ($this->block_no_js_visitor) {
                $this->verdict->error = $e->getMessage();
                $this->verdict->allow = false;
                $this->verdict->comment = 'Please, enable JavaScript to process the form.';
            } else {
                $this->verdict->allow = true;
            }
        }
    }

    /**
     * Check if the access key is valid.
     *
     * @throws \Exception If the access key is invalid
     */
    private function checkAccessKey()
    {
        if (empty($this->access_key)) {
            throw new \Exception('Access key is empty');
        }

        if (!is_string($this->access_key)) {
            throw new \Exception('Access key is not a string');
        }
    }

    /**
     * Check if the event token is valid.
     *
     * @throws \Exception If the event token is invalid
     */
    private function checkEventToken()
    {
        if (empty($this->event_token)) {
            throw new \Exception('Event token is empty');
        }

        if (!is_string($this->event_token)) {
            throw new \Exception('Event token is not a string');
        }

        if (strlen($this->event_token) !== 64) {
            throw new \Exception('Event token is not valid');
        }
    }

    /**
     * Perform actions before returning the verdict.
     *
     * @return CleantalkVerdict Verdict object with the result of the CleanTalk check
     */
    private function beforeReturnVerdict()
    {
        $this->setImprovementSuggestions();
        return $this->verdict;
    }

    /**
     * ------------ Fluid public calls ------------
     */

    /**
     * Set the email of the sender.
     *
     * @param string $email Email of the sender
     * @return $this
     */
    public function setEmail($email)
    {
        $this->fluidCallStack(__FUNCTION__);
        $this->email = is_string($email) ? $email : null;
        return $this;
    }

    /**
     * Set the nickname of the sender.
     *
     * @param string $nickname Nickname of the sender
     * @return $this
     */
    public function setNickName($nickname)
    {
        $this->fluidCallStack(__FUNCTION__);
        $this->nickname = is_string($nickname) ? $nickname : null;
        return $this;
    }

    /**
     * Set the message content.
     *
     * @param string $message Message content
     * @return $this
     */
    public function setMessage($message)
    {
        $this->fluidCallStack(__FUNCTION__);
        $this->message =  is_string($message) ? $message : null;
        return $this;
    }

    /**
     * Set the IP address of the sender.
     *
     * @param string|null $ip IP address of the sender
     * @return $this
     */
    public function setIP($ip = null)
    {
        $this->fluidCallStack(__FUNCTION__);
        if (!Helper::ipValidate($ip)) {
            $this->setImprovementSuggestion('critical', 'IP address is not valid, the value has been set form the request', 'setIP()');
        } else {
            $this->ip = $ip;
        }

        return $this;
    }

    /**
     * Enable blocking of visitors without JavaScript.
     *
     * @return $this
     */
    public function setDoBlockNoJSVisitor()
    {
        $this->fluidCallStack(__FUNCTION__);
        $this->block_no_js_visitor = true;
        return $this;
    }

    /**
     * Set the event token.
     *
     * @param string|null $event_token Event token
     * @return $this
     */
    public function setEventTokenEnabled($event_token_enabled = null)
    {
        $this->fluidCallStack(__FUNCTION__);
        $this->event_token_enabled = $event_token_enabled;
        return $this;
    }

    /**
     * Set the event token.
     *
     * @param string|null $event_token Event token
     * @return $this
     */
    public function setEventToken($event_token = null)
    {
        $this->fluidCallStack(__FUNCTION__);
        $this->event_token = $event_token;
        return $this;
    }

    /**
     * Use the registration check method.
     *
     * @return $this
     */
    public function useRegistrationCheck()
    {
        $this->fluidCallStack(__FUNCTION__);
        $this->method_name = 'check_newuser';
        return $this;
    }

    /**
     * Use the contact form check method.
     *
     * @return $this
     */
    public function useContactFormCheck()
    {
        $this->fluidCallStack(__FUNCTION__);
        $this->method_name = 'check_message';
        return $this;
    }

    /**
     * Set own data container.
     * @param $data_container
     *
     * @return $this
     */
    public function setCustomFormDataContainer($data_container)
    {
        $this->data_container = $data_container;
        return $this;
    }

    /**
     * Get the verdict from the CleanTalk API.
     *
     * @return CleantalkVerdict Verdict object with the result of the CleanTalk check
     */
    public function handle()
    {
        $this->verifyData();

        if ($this->verdict->error) {
            return $this->beforeReturnVerdict();
        }

        if (empty($this->method_name)) {
            $this->method_name = empty($this->message) ? 'check_newuser' : 'check_message';
        }

        $this->cleantalk_response = $this->getCleanTalkResponse();

        if ($this->cleantalk_response->error) {
            /** @psalm-suppress InvalidOperand */
            $this->verdict->error = 'CleanTalk moderate server error: ' . $this->cleantalk_response->error;
            return $this->beforeReturnVerdict();
        }

        $this->verdict->allow = $this->cleantalk_response->allow;
        $this->verdict->comment = $this->cleantalk_response->comment;
        $this->verdict->request_link = !empty($this->cleantalk_response->id)
            ? 'https://cleantalk.org/my/show_requests?request_id=' . $this->cleantalk_response->id
            : null
        ;

        return $this->beforeReturnVerdict();
    }

    /**
     * ------------ Improvement suggestions feature ------------
     */

    /**
     * Set suggestions for improving the data quality.
     */
    private function setImprovementSuggestions()
    {
        if ( $this->cleantalk_response instanceof CleantalkResponse ) {
            if (empty($this->cleantalk_response->comment)) {
                $this->setImprovementSuggestion(
                    'critical',
                    'Something is wrong with connection to the CleanTalk server ' . static::MODERATE_URL,
                    'getCleanTalkResponse()'
                );
                return;
            }
            if ($this->cleantalk_response->error) {
                $this->setImprovementSuggestion(
                    'critical',
                    'Please, check the error message from the CleanTalk server',
                    'getCleanTalkResponse()'
                );
                return;
            }
            if ($this->cleantalk_response->account_status !== 1) {
                $this->setImprovementSuggestion(
                    'critical',
                    'Something wrong with your CleanTalk license, visit your CleanTalk dashboard to check the license status',
                    'getCleanTalkResponse()'
                );
                return;
            }
        }

        if (!empty($this->verdict->error)) {
            $this->setImprovementSuggestion('critical', 'Error occurred due the CleanTalk check: ' . $this->verdict->error);
        }

        if (empty($this->ip)) {
            $fluid_method = 'setIP';
            $stack = !$this->fluidCallExist($fluid_method)
                ? "interface method ->$fluid_method() has not been called"
                : "interface method ->$fluid_method() has been called, but provided var is invalid or automatic IP get has failed";
            $this->setImprovementSuggestion(
                'average',
                'Please, provide the visitor IP address to improve check quality.',
                $stack
            );
        }

        if (empty($this->event_token)) {
            $fluid_method = 'setEventToken';
            $stack = !$this->fluidCallExist($fluid_method)
                ? "interface method ->$fluid_method() has not been called, make sure the form data contains the field " . static::EVENT_TOKEN_FIELD_NAME
                : "interface method ->$fluid_method() has been called, but provided var is invalid";
            $common_token_message = 'Event token is not provided. Most likely the visitor has JavaScript disabled.';
            $this->setImprovementSuggestion('critical', $common_token_message, $stack);

            $fluid_method = 'setDoBlockNoJSVisitor';
            if ($this->fluidCallExist($fluid_method)) {
                $stack = "seen the call ->$fluid_method()";
                $common_token_message .= ' All the visitors without token are BLOCKED due the current setting to block users without JS.';
            } else {
                $stack = "interface method ->$fluid_method() has not been called";
                $common_token_message .= ' All the visitors without token are PASSED due the current setting to pass users without JS.';
            }
            $this->setImprovementSuggestion('critical', $common_token_message, $stack);
        }

        if (empty($this->access_key)) {
            $this->setImprovementSuggestion(
                'critical',
                'Please, provide the access key via constructor call ' . __CLASS__ . '()',
                'construct()'
            );
        }

        if (empty($this->email)) {
            $fluid_method = 'setEmail';
            $stack = !$this->fluidCallExist($fluid_method)
                ? "interface method ->$fluid_method() has not been called"
                : "interface method ->$fluid_method() has been called, but provided var is invalid";
            $this->setImprovementSuggestion(
                'average',
                'Please, provide the email field content to improve check quality.',
                $stack
            );
        }

        if (empty($this->nickname)) {
            $fluid_method = 'setNickName';
            $stack = !$this->fluidCallExist($fluid_method)
                ? "interface method ->$fluid_method() has not been called"
                : "interface method ->$fluid_method() has been called, but provided var is invalid";
            $this->setImprovementSuggestion(
                'average',
                'Please, provide the nickname field content to improve check quality.',
                $stack
            );
        }

        if (empty($this->message)) {
            if ($this->fluidCallExist('useContactFormCheck')) {
                if ($this->fluidCallExist('setMessage')) {
                    $stack = 'seen the call ->setMessage(), but provided value is invalid';
                } else {
                    $stack = 'seen the call ->useContactFormCheck(), but interface method ->setMessage() has not been called';
                }
                $this->setImprovementSuggestion(
                    'average',
                    'Please, provide the message field to improve check quality.',
                    $stack
                );
            }
        }
    }

    /**
     * Set an improvement suggestion.
     *
     * @param string $level Severity level of the suggestion
     * @param string $message Suggestion message
     * @param string|null $stack Call stack information
     */
    private function setImprovementSuggestion($level, $message, $stack = null)
    {
        $this->improvement_suggestions[$level][] = array('stack' => $stack, 'message' => $message);
    }

    /**
     * Get the improvement suggestions.
     *
     * @return array Improvement suggestions
     */
    private function getImprovementSuggestions()
    {
        if (empty($this->improvement_suggestions)) {
            return array('Everything looks well!');
        }
        ksort($this->improvement_suggestions, SORT_STRING);
        return $this->improvement_suggestions;
    }

    /**
     * Add a method to the fluid call stack.
     *
     * @param string $method Method name
     */
    private function fluidCallStack($method)
    {
        $this->fluid_call_stack[] = $method;
    }

    /**
     * Check if a method exists in the fluid call stack.
     *
     * @param string $method Method name
     * @return bool True if the method exists in the stack, false otherwise
     */
    private function fluidCallExist($method)
    {
        return in_array($method, $this->fluid_call_stack);
    }

    /**
     * Get the suggestions for improving the data quality.
     * @param $return_as_json
     *
     * @return false|string
     */
    public function whatsWrong($return_as_json = false)
    {
        $array = array(
            'suggestions' => $this->getImprovementSuggestions(),
            'request_data' => $this->getCleanTalkRequestData(),
            'verdict' => $this->verdict instanceof CleantalkVerdict ? $this->verdict->getArray() : null,
        );

        if (empty($array['verdict'])) {
            $array['verdict'] = 'Verdict is not processed. Maybe you forgot to call ->getVerdict() method before';
        }

        if ($return_as_json) {
            return @json_encode($array);
        }

            /** @psalm-suppress InvalidScalarArgument */
            $suggestions = var_export($array['suggestions'], 1);
            /** @psalm-suppress InvalidScalarArgument */
            $data  = var_export($array['request_data'], 1);
            /** @psalm-suppress InvalidScalarArgument */
            $verdict = var_export($array['verdict'], 1);
        echo "<div>Suggestions<pre>$suggestions</pre></div>";
        echo "<div>Request Data<pre>$data</pre></div>";
        echo "<div>Verdict<pre>$verdict</pre></div>";
        return '';
    }
}
