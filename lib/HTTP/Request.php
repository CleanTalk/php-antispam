<?php

namespace CleanTalk\HTTP;

/**
 * Class Request
 *
 * @version       1.0.0
 * @package       Cleantalk\Common\Helpers
 * @author        Cleantalk team (welcome@cleantalk.org)
 * @copyright (C) CleanTalk team (http://cleantalk.org)
 * @license       GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 * @see           https://github.com/CleanTalk/security-malware-firewall
 *
 * @psalm-suppress PossiblyUndefinedIntArrayOffset
 */
class Request
{
    /**
     * Default user agent for HTTP requests
     */
    const AGENT = 'Cleantalk-Helper/1.0.0';

    /**
     * @var string|string[] Single URL string or array of URLs for multi request
     */
    protected $url;

    /**
     * @var array POST|GET indexed array with data to send
     */
    protected $data = [];

    /**
     * @var string[] Array with presets
     *                          Example: array('get_code', 'async')
     *                      Or space separated string with presets
     *                          Example: 'get_code async get'
     *
     * May use the following presets(combining is possible):
     *      dont_follow_redirects - ignore 300-family response code and don't follow redirects
     *      get_code              - getting only HTTP response code
     *      async                 - async requests. Sends request and return 'true' value. Doesn't wait for response.
     *      get                   - makes GET-type request instead of default POST-type
     *      ssl                   - uses SSL
     *      cache                 - allow caching for this request
     *      retry_with_socket     - make another request with socket if cURL failed to retrieve data
     */
    protected $presets = [];

    /**
     * @var array Optional options for CURL connection
     *              Example: array(
     *                   CURLOPT_URL            => $url,
     *                   CURLOPT_TIMEOUT        => 15,
     *                   CURLOPT_LOW_SPEED_TIME => 10,
     *                   CURLOPT_RETURNTRANSFER => true,
     *            )
     */
    protected $options = [];

    /**
     * @var array [callable] Callback function to process after the request is performed without error to process received data
     *               If passed will be fired for both single and multi requests
     */
    protected $callbacks = [];

    /**
     * @var Response|array<Response>
     */
    public $response;

    /**
     * @param mixed $url
     *
     * @return Request
     */
    public function setUrl($url)
    {
        $this->url = $url;

        return $this;
    }

    /**
     * @param mixed $data
     *
     * @return Request
     */
    public function setData($data)
    {
        // If $data scalar converting it to array
        $this->data = ! empty($data) && ! self::isJson($data) && is_scalar($data)
            ? array((string)$data => 1)
            : $data;

        return $this;
    }

    /**
     * Set one or more presets which change the way of the processing Request::request
     *
     * @param mixed $presets Array with presets
     *                          Example: array('get_code', 'async')
     *                      Or space separated string with presets
     *                          Example: 'get_code async get'
     *
     * May use the following presets(combining is possible):
     *      dont_follow_redirects - ignore 300-family response code and don't follow redirects
     *      get_code              - getting only HTTP response code
     *      async                 - async requests. Sends request and return 'true' value. Doesn't wait for response.
     *      get                   - makes GET-type request instead of default POST-type
     *      ssl                   - uses SSL
     *      cache                 - allow caching for this request
     *      retry_with_socket     - make another request with socket if cURL failed to retrieve data
     *
     * @return Request
     */
    public function setPresets($presets)
    {
        // Prepare $presets to process
        $this->presets = ! is_array($presets)
            ? explode(' ', $presets)
            : $presets;

        return $this;
    }

    /**
     * @param mixed $options
     *
     * @return Request
     */
    public function setOptions($options)
    {
        $this->options = $options;

        return $this;
    }

    /**
     * Set callback and additional arguments which will be passed to callback function
     *
     * @param callable $callback
     * @param array $arguments
     * @param int $priority
     * @param bool $pass_response
     *
     * @return Request
     * @psalm-suppress UnusedVariable
     */
    public function addCallback($callback, $arguments = array(), $priority = null, $pass_response = false)
    {
        $priority = $priority ?: 100;
        if ( isset($this->callbacks[$priority]) ) {
            return $this->addCallback($callback, $arguments, ++$priority);
        }

        $this->callbacks[$priority] = [
            'function'      => $callback,
            'arguments'     => $arguments,
            'pass_response' => $pass_response,
        ];

        return $this;
    }

    /**
     * Function sends raw http request
     *
     * @return array|bool (array || array('error' => true))
     */
    public function request()
    {
        // Return the error if cURL is not installed
        if ( ! function_exists('curl_init') ) {
            return array('error' => 'CURL_NOT_INSTALLED');
        }

        if ( empty($this->url) ) {
            return array('error' => 'URL_IS_NOT_SET');
        }

        $this->convertOptionsTocURLFormat();
        $this->appendOptionsObligatory();
        $this->processPresets();

        // Call cURL multi request if many URLs passed
        $this->response = is_array($this->url)
            ? $this->requestMulti()
            : $this->requestSingle();

        // Process the error. Unavailable for multiple URLs.
        if (
            ! is_array($this->url) &&
            ! is_array($this->response) && $this->response->getError() &&
            in_array('retry_with_socket', $this->presets, true)
        ) {
            $this->response = $this->requestWithSocket();
            if ( $this->response->getError() ) {
                return $this->response->getError();
            }
        }

        return $this->runCallbacks();
    }

    /**
     * @return Response
     */
    protected function requestSingle()
    {
        // Make a request
        $ch = curl_init();

        curl_setopt_array($ch, $this->options);

        $request_result = curl_exec($ch);    // Gather request result
        $curl_info      = curl_getinfo($ch); // Gather HTTP response information

        // Do not catch timeout error for async requests.
        if ( in_array('async', $this->presets, true) ) {
            $request_result = true;
        }

        if ( $request_result === false ) {
            $request_result = array('error' => curl_error($ch));
        }

        curl_close($ch);


        return new Response($request_result, $curl_info);
    }


    /**
     * Do multi curl requests without processing it.
     *
     * @return array<Response>
     *
     * @psalm-suppress PossiblyInvalidArgument
     */
    protected function requestMulti()
    {
        $this->response = [];

        if ( ! is_array($this->url) ) {
            return $this->response;
        }

        $urls_count     = count($this->url);
        $curl_arr       = array();
        $mh             = curl_multi_init();

        for ( $i = 0; $i < $urls_count; $i++ ) {
            $this->options[CURLOPT_URL] = $this->url[$i];
            $curl_arr[$i]               = curl_init($this->url[$i]);

            curl_setopt_array($curl_arr[$i], $this->options);
            curl_multi_add_handle($mh, $curl_arr[$i]);
        }

        do {
            curl_multi_exec($mh, $running);
            usleep(1000);
        } while ( $running > 0 );

        for ( $i = 0; $i < $urls_count; $i++ ) {
            $curl_info     = curl_getinfo($curl_arr[$i]); // Gather HTTP response information
            $received_data = curl_multi_getcontent($curl_arr[$i]);

            // Do not catch timeout error for async requests.
            if ( in_array('async', $this->presets, true) ) {
                $received_data = true;
            }

            if ( $received_data === '' ) {
                $received_data = array('error' => curl_error($curl_arr[$i]));
            }

            $this->response[$this->url[$i]] = new Response($received_data, $curl_info);
        }

        return $this->response;
    }

    /**
     * Make a request with socket, exactly with file_get_contents()
     *
     * @return Response
     *
     * @psalm-suppress PossiblyInvalidArgument
     * @psalm-suppress PossiblyInvalidCast
     */
    private function requestWithSocket()
    {
        if ( ! ini_get('allow_url_fopen') ) {
            return new Response(['error' => 'ALLOW_URL_FOPEN_IS_DISABLED'], []);
        }

        $context = stream_context_create(
            [
                'http' => [
                    'method'  => 'GET', //in_array('get', $this->presets, true) ? 'GET' : 'POST',
                    'timeout' => $this->options[CURLOPT_TIMEOUT],
                    'content' => $this->data,
                ],
            ]
        );

        $response_content = @file_get_contents($this->url, false, $context)
            ?: ['error' => 'FAILED_TO_USE_FILE_GET_CONTENTS'];

        return new Response($response_content, []);
    }

    // Process with callback if passed. Save the processed result.
    protected function runCallbacks()
    {
        $return_value = [];

        // Cast to array to process result from $this->requestSingle as $this->requestMulti results
        $responses = is_object($this->response)
            ? [$this->response]
            : $this->response;

        // Sort callback to keep the priority order
        ksort($this->callbacks);

        foreach ( $responses as $url => &$response ) {
            // Skip the processing if the error occurred in this specific result
            if ( $response->getError() ) {
                $return_value[] = $response->getError();
                continue;
            }

            // Get content to process
            $content = $response->getContentProcessed();

            // Perform all provided callback functions to each request result
            if ( ! empty($this->callbacks) ) {
                foreach ( $this->callbacks as $callback ) {
                    if ( is_callable($callback['function']) ) {
                        // Run callback
                        $content = call_user_func_array(
                            $callback['function'],
                            array_merge(
                                array(
                                    $callback['pass_response'] ? $response : $content, // Pass Response or content
                                    $url
                                ),
                                $callback['arguments']
                            )
                        );

                        // Foolproof
                        if ( ! $content instanceof Response ) {
                            $response->setProcessed($content);
                        }
                    }
                }
            }

            $return_value[$url] = $content instanceof Response ? $content->getContentProcessed() : $content;
        }
        unset($response);

        // Return a single content if it was a single request
        return is_array($this->response) && count($this->response) > 1
            ? $return_value
            : reset($return_value);
    }

    /**
     * Convert given options from simple naming like 'timeout' or 'ssl'
     *  to sophisticated and standardized cURL defined constants
     *
     *  !! Called only after we make sure that cURL is exists !!
     */
    private function convertOptionsTocURLFormat()
    {
        $temp_options = [];
        foreach ( $this->options as $option_name => &$option_value ) {
            switch ( $option_name ) {
                case 'timeout':
                    $temp_options[CURLOPT_TIMEOUT] = $option_value; // String
                    unset($this->options[$option_name]);
                    break;
                case 'sslverify':
                    if ( $option_value ) {
                        $temp_options[CURLOPT_SSL_VERIFYPEER] = (bool)$option_value;      // Boolean
                        $temp_options[CURLOPT_SSL_VERIFYHOST] = (int)(bool)$option_value; // Int 0|1
                        unset($this->options[$option_name]);
                    }
                    break;
                case 'sslcertificates':
                    $temp_options[CURLOPT_CAINFO] = $option_name; // String
                    unset($this->options[$option_name]);
                    break;
                case 'headers':
                    $temp_options[CURLOPT_HTTPHEADER] = $option_name; // String[]
                    unset($this->options[$option_name]);
                    break;
                case 'user-agent':
                    $temp_options[CURLOPT_USERAGENT] = $option_name; // String
                    unset($this->options[$option_name]);
                    break;

                // Unset unsupported string names in options
                default:
                    if ( ! is_int($option_name) ) {
                        unset($this->options[$option_name]);
                    }
                    break;
            }
        }
        unset($option_value);

        $this->options = array_replace($this->options, $temp_options);
    }

    /**
     * Set default options to make a request
     */
    protected function appendOptionsObligatory()
    {
        // Merging OBLIGATORY options with GIVEN options
        $this->options = array_replace(
            array(
                CURLOPT_URL            => ! is_array($this->url) ? $this->url : null,
                CURLOPT_TIMEOUT        => 50,
                CURLOPT_LOW_SPEED_TIME => 25,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_CONNECTTIMEOUT => 5000,
                CURLOPT_FORBID_REUSE   => true,
                CURLOPT_USERAGENT      => self::AGENT,
                CURLOPT_POST           => true,
                CURLOPT_POSTFIELDS     => $this->data,
                CURLOPT_SSL_VERIFYPEER => false,
                CURLOPT_SSL_VERIFYHOST => 0,
                CURLOPT_HTTPHEADER     => array(
                    'Expect:',
                    // Fix for large data and old servers http://php.net/manual/ru/function.curl-setopt.php#82418
                    'Expires: ' . date(DATE_RFC822, mktime(0, 0, 0, 1, 1, 1971)),
                    'Cache-Control: no-store, no-cache, must-revalidate',
                    'Cache-Control: post-check=0, pre-check=0',
                    'Pragma: no-cache',
                ),
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_MAXREDIRS      => 5,
            ),
            $this->options
        );
    }

    /**
     * Append options considering passed presets
     */
    protected function processPresets()
    {
        foreach ( $this->presets as $preset ) {
            switch ( $preset ) {
                // Do not follow redirects
                case 'dont_follow_redirects':
                    $this->options[CURLOPT_FOLLOWLOCATION] = false;
                    $this->options[CURLOPT_MAXREDIRS]      = 0;
                    break;

                // Get headers only
                case 'get_code':
                    $this->options[CURLOPT_HEADER] = true;
                    $this->options[CURLOPT_NOBODY] = true;
                    $this->addCallback(
                        static function (Response $response, $_url) {
                            return $response->getResponseCode();
                        },
                        array(),
                        60,
                        true
                    );
                    break;

                // Get headers only
                case 'split_to_array':
                    $this->addCallback(
                        static function ($response_content, $_url) {
                            return explode(PHP_EOL, $response_content);
                        },
                        array(),
                        50
                    );
                    break;

                // Make a request, don't wait for an answer
                case 'async':
                    $this->options[CURLOPT_CONNECTTIMEOUT] = 3;
                    $this->options[CURLOPT_TIMEOUT]        = 3;
                    break;

                case 'get':
                    $this->options[CURLOPT_CUSTOMREQUEST] = 'GET';
                    $this->options[CURLOPT_POST]          = false;
                    $this->options[CURLOPT_POSTFIELDS]    = null;
                    // Append parameter in a different way for single and multiple requests
                    if ( is_array($this->url) ) {
                        $this->url = array_map(function ($elem) {
                            return self::appendParametersToURL($elem, $this->data);
                        }, $this->url);
                    } else {
                        $this->options[CURLOPT_URL] = self::appendParametersToURL(
                            $this->options[CURLOPT_URL],
                            $this->data
                        );
                    }
                    break;

                case 'ssl':
                    $this->options[CURLOPT_SSL_VERIFYPEER] = true;
                    $this->options[CURLOPT_SSL_VERIFYHOST] = 2;
                    if ( defined('APBCT_CASERT_PATH') && APBCT_CASERT_PATH ) {
                        $this->options[CURLOPT_CAINFO] = APBCT_CASERT_PATH;
                    }
                    break;

                case 'no_cache':
                    // Append parameter in a different way for single and multiple requests
                    if ( is_array($this->url) ) {
                        $this->url = array_map(static function ($elem) {
                            return self::appendParametersToURL($elem, ['apbct_no_cache' => mt_rand()]);
                        }, $this->url);
                    } else {
                        $this->options[CURLOPT_URL] = self::appendParametersToURL(
                            $this->options[CURLOPT_URL],
                            ['apbct_no_cache' => mt_rand()]
                        );
                    }
                    break;
                case 'api3.0':
                    // api3.0 methods requires 'Content-Type: application/json' http header
                    $this->options[CURLOPT_HTTPHEADER][] = 'Content-Type: application/json';
            }
        }
    }

    /**
     * Appends given parameter(s) to URL considering other parameters
     * Adds ? or & before the append
     *
     * @param string $url
     * @param string|array $parameters
     *
     * @return string
     */
    public static function appendParametersToURL($url, $parameters)
    {
        if ( empty($parameters) ) {
            return $url;
        }

        $parameters = is_array($parameters)
            ? http_build_query($parameters)
            : $parameters;

        $url .= strpos($url, '?') === false
            ? ('?' . $parameters)
            : ('&' . $parameters);

        return $url;
    }

    /**
     * Checks if the string is JSON type
     *
     * @param string $string
     *
     * @return bool
     */
    public static function isJson($string)
    {
        return is_string($string) && is_array(json_decode($string, true));
    }
}
