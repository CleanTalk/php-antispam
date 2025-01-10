<?php

namespace Cleantalk;

class CleantalkAPI
{
    const URL = 'https://api.cleantalk.org';

    /**
     * Function gets access key automatically
     *
     * @param string $email website admin email
     * @param string $host website host
     * @param string $platform website platform
     *
     * @return string
     */
    public static function method__get_api_key( // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
        $email,
        $host,
        $platform,
        $timezone = null,
        $language = null,
        $ip = null,
        $white_label = 0,
        $hoster_api_key = '',
        $do_check = true
    ) {
        $request = array(
            'method_name'          => 'get_api_key',
            'product_name'         => 'antispam',
            'email'                => $email,
            'website'              => $host,
            'platform'             => $platform,
            'timezone'             => $timezone,
            'http_accept_language' => $language,
            'user_ip'              => $ip,
            'hoster_whitelabel'    => $white_label,
            'hoster_api_key'       => $hoster_api_key,
        );

        $result = self::send_request($request);
        $result = $do_check ? self::check_response($result, 'get_api_key') : $result;

        return $result;
    }

    /**
     * Function gets spam report
     *
     * @param string $host website host
     * @param integer $period report days
     * @param bool $do_check do_check
     *
     * @return string
     */
    public static function method__get_antispam_report($host, $period = 1, $do_check = true) // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        $request = array(
            'method_name' => 'get_antispam_report',
            'hostname'    => $host,
            'period'      => $period
        );

        $result = self::send_request($request);
        $result = $do_check ? self::check_response($result, 'get_antispam_report') : $result;

        return $result;
    }

    /**
     * Function gets spam statistics
     *
     * @param string $api_key
     * @param bool $do_check
     *
     * @return string
     */
    public static function method__get_antispam_report_breif($api_key, $do_check = true) // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        $request = array(
            'method_name' => 'get_antispam_report_breif',
            'auth_key'    => $api_key,
        );

        $result = self::send_request($request);
        $result = $do_check ? self::check_response($result, 'get_antispam_report_breif') : $result;

        return $result;
    }

    /**
     * Function gets information about renew notice
     *
     * @param string $api_key
     * @param string $path_to_cms
     * @param bool $do_check
     *
     * @return string
     */
    public static function method__notice_validate_key($api_key = '', $path_to_cms = '', $do_check = true) // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        $request = array(
            'method_name' => 'notice_validate_key',
            'auth_key'    => $api_key,
            'path_to_cms' => $path_to_cms
        );

        $result = self::send_request($request);
        $result = $do_check ? self::check_response($result, 'notice_validate_key') : $result;

        return $result;
    }

    /**
     * Function gets information about renew notice
     *
     * @param string api_key
     *
     * @return string
     */
    public static function method__notice_paid_till($api_key, $do_check = true) // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        $request = array(
            'method_name' => 'notice_paid_till',
            'auth_key'    => $api_key
        );

        $result = self::send_request($request);
        $result = $do_check ? self::check_response($result, 'notice_paid_till') : $result;

        return $result;
    }

    /**
     * Function sends raw request to API server
     *
     * @param array $data to send
     * @param string $url of API server
     * @param int $timeout is data have to be JSON encoded or not
     * @param bool $ssl should use ssl
     * @psalm-suppress PossiblyUnusedParam
     * @return string JSON encoded string
     */
    public static function send_request($data, $url = self::URL, $timeout = 5, $ssl = false) // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        // Possibility to switch API url
        $url = defined('CLEANTALK_API_URL') ? CLEANTALK_API_URL : $url;

        // Adding agent version to data
        if ( defined('CLEANTALK_AGENT') ) {
            $data['agent'] = CLEANTALK_AGENT;
        }

        // Make URL string
        $data_string = http_build_query($data);
        $data_string = str_replace("&amp;", "&", $data_string);

        if ( function_exists('curl_init') ) {
            $ch = curl_init();

            // Set diff options
            curl_setopt($ch, CURLOPT_URL, $url);
            curl_setopt($ch, CURLOPT_TIMEOUT, $timeout);
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $data_string);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_HTTPHEADER, array('Expect:'));

            // Switch on/off SSL
            if ( $ssl === true ) {
                curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
                curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
            } else {
                curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
                curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
            }

            // Make a request
            $result = curl_exec($ch);
            $errors = curl_error($ch);
            curl_close($ch);

            // Get cURL error if result failed
            if ( $result === false ) {
                // And retry with SSL enabled
                if ( $ssl === false ) {
                    return self::send_request($data, $url, $timeout, true);
                }
            }
        } else {
            $errors = 'CURL_NOT_INSTALLED';
        }

        // Trying to use file_get_contents() to make a API call
        if ( ! empty($errors) && ini_get('allow_url_fopen') ) {
            $opts    = array(
                'http' => array(
                    'method'  => "POST",
                    'timeout' => $timeout,
                    'content' => $data_string,
                )
            );
            $context = stream_context_create($opts);
            $result  = file_get_contents($url, false, $context);
        } else {
            $errors .= '_AND_ALLOW_URL_FOPEN_IS_DISABLED';
        }

        if ( empty($result) && ! empty($errors) ) {
            $json_error = json_encode(array('error' => true, 'error_string' => $errors));
            return false !== $json_error ? $json_error : 'CURL_ERROR';
        }

        return $result;
    }

    /**
     * Function checks server response
     *
     * @param string $result
     * @param string|null $method_name
     *
     * @return string JSON encoded string
     */
    public static function check_response($result, $method_name = null) // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        $out = array('error' => false);

        // Errors handling

        // Bad connection
        if ( empty($result) ) {
            $out = array(
                'error'        => true,
                'error_string' => 'CONNECTION_ERROR'
            );
        }

        // JSON decode errors
        $result = json_decode($result, true);
        if ( empty($result) ) {
            $out = array(
                'error'        => true,
                'error_string' => 'JSON_DECODE_ERROR'
            );
        }

        // cURL error
        if ( ! empty($result['error']) ) {
            $out = array(
                'error'        => true,
                'error_string' => 'CONNECTION_ERROR: ' . $result['error_string'],
            );
        }

        // Server errors
        if ( $result && (isset($result['error_no']) || isset($result['error_message'])) ) {
            $out = array(
                'error'         => true,
                'error_string'  => "SERVER_ERROR NO: {$result['error_no']} MSG: {$result['error_message']}",
                'error_no'      => $result['error_no'],
                'error_message' => $result['error_message']
            );
        }

        // Patches for different methods
        if ( !$out['error'] ) {
            // mehod_name = notice_validate_key
            if ( $method_name == 'notice_validate_key' && isset($result['valid']) ) {
                $out = $result;
            }

            // Other methods
            if ( isset($result['data']) && is_array($result['data']) ) {
                $out = $result['data'];
            }
        }

        // method_name = get_antispam_report_breif
        if ( $method_name == 'get_antispam_report_breif' ) {
            if ( !$out['error'] ) {
                $result = $result['data'];
            }

            for ( $tmp = array(), $i = 0; $i < 7; $i++ ) {
                $tmp[date('Y-m-d', time() - 86400 * 7 + 86400 * $i)] = 0;
            }

            $result['spam_stat']    = array_merge($tmp, isset($result['spam_stat']) ? $result['spam_stat'] : array());
            $result['top5_spam_ip'] = isset($result['top5_spam_ip']) ? $result['top5_spam_ip'] : array();
            $out                    = array_merge($result, $out);
        }

        $out = json_encode($out);

        return false !== $out ? $out : 'JSON_ENCODE_ERROR';
    }
}
