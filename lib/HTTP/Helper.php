<?php

namespace CleanTalk\HTTP;

/**
 * CleanTalk Helper class.
 * Compatible with any CMS.
 *
 * @package       PHP Anti-Spam by CleanTalk
 * @subpackage    Helper
 * @Version       4.1
 * @author        Cleantalk team (welcome@cleantalk.org)
 * @copyright (C) 2014 CleanTalk team (http://cleantalk.org)
 * @license       GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 * @see           https://github.com/CleanTalk/php-antispam
 */
class Helper
{
    /**
     * @var array Set of private networks IPv4 and IPv6
     */
    public static $private_networks = array(
        'v4' => array(
            '10.0.0.0/8',
            '100.64.0.0/10',
            '172.16.0.0/12',
            '192.168.0.0/16',
            '127.0.0.1/32',
        ),
        'v6' => array(
            '0:0:0:0:0:0:0:1/128', // localhost
            '0:0:0:0:0:0:a:1/128', // ::ffff:127.0.0.1
        ),
    );

    /**
     * Getting arrays of IP (REMOTE_ADDR, X-Forwarded-For, X-Real-Ip, Cf_Connecting_Ip)
     *
     * @param string $ip_type_to_get Type of IP you want to receive
     * @param bool $v4_only
     *
     * @return string|null
     *
     * @psalm-suppress InvalidReturnStatement
     * @psalm-suppress ComplexMethod
     * @psalm-suppress FalsableReturnStatement
     */
    public static function ipGet($ip_type_to_get = 'real', $v4_only = true, $headers = array())
    {
        $out = null;
        switch ($ip_type_to_get) {
            // Cloud Flare
            case 'cloud_flare':
                $headers = $headers ?: self::httpGetHeaders();
                if (
                    isset($headers['Cf-Connecting-Ip']) &&
                    (isset($headers['Cf-Ray']) || isset($headers['X-Wpe-Request-Id'])) &&
                    ! isset($headers['X-Gt-Clientip'])
                ) {
                    if (isset($headers['Cf-Pseudo-Ipv4'], $headers['Cf-Pseudo-Ipv6'])) {
                        $source = $headers['Cf-Pseudo-Ipv6'];
                    } else {
                        $source = $headers['Cf-Connecting-Ip'];
                    }
                    $tmp = strpos($source, ',') !== false
                        ? explode(',', $source)
                        : (array)$source;
                    if ( isset($tmp[0]) ) {
                        $ip_version = self::ipValidate(trim($tmp[0]));
                        if ($ip_version) {
                            $out = $ip_version === 'v6' && ! $v4_only
                                ? self::ipV6Normalize(trim($tmp[0]))
                                : trim($tmp[0]);
                        }
                    }
                }
                break;

            // GTranslate
            case 'gtranslate':
                $headers = $headers ?: self::httpGetHeaders();
                if (isset($headers['X-Gt-Clientip'], $headers['X-Gt-Viewer-Ip'])) {
                    $ip_version = self::ipValidate($headers['X-Gt-Viewer-Ip']);
                    if ($ip_version) {
                        $out = $ip_version === 'v6' && ! $v4_only ? self::ipV6Normalize(
                            $headers['X-Gt-Viewer-Ip']
                        ) : $headers['X-Gt-Viewer-Ip'];
                    }
                }
                break;

            // ezoic
            case 'ezoic':
                $headers = $headers ?: self::httpGetHeaders();
                if (isset($headers['X-Middleton'], $headers['X-Middleton-Ip'])) {
                    $ip_version = self::ipValidate($headers['X-Middleton-Ip']);
                    if ($ip_version) {
                        $out = $ip_version === 'v6' && ! $v4_only ? self::ipV6Normalize(
                            $headers['X-Middleton-Ip']
                        ) : $headers['X-Middleton-Ip'];
                    }
                }
                break;

            // Sucury
            case 'sucury':
                $headers = $headers ?: self::httpGetHeaders();
                if (isset($headers['X-Sucuri-Clientip'])) {
                    $ip_version = self::ipValidate($headers['X-Sucuri-Clientip']);
                    if ($ip_version) {
                        $out = $ip_version === 'v6' && ! $v4_only ? self::ipV6Normalize(
                            $headers['X-Sucuri-Clientip']
                        ) : $headers['X-Sucuri-Clientip'];
                    }
                }
                break;

            // X-Forwarded-By
            case 'x_forwarded_by':
                $headers = $headers ?: self::httpGetHeaders();
                if (isset($headers['X-Forwarded-By'], $headers['X-Client-Ip'])) {
                    $ip_version = self::ipValidate($headers['X-Client-Ip']);
                    if ($ip_version) {
                        $out = $ip_version === 'v6' && ! $v4_only ? self::ipV6Normalize(
                            $headers['X-Client-Ip']
                        ) : $headers['X-Client-Ip'];
                    }
                }
                break;

            // Stackpath
            case 'stackpath':
                $headers = $headers ?: self::httpGetHeaders();
                if (isset($headers['X-Sp-Edge-Host'], $headers['X-Sp-Forwarded-Ip'])) {
                    $ip_version = self::ipValidate($headers['X-Sp-Forwarded-Ip']);
                    if ($ip_version) {
                        $out = $ip_version === 'v6' && ! $v4_only ? self::ipV6Normalize(
                            $headers['X-Sp-Forwarded-Ip']
                        ) : $headers['X-Sp-Forwarded-Ip'];
                    }
                }
                break;

            // Ico-X-Forwarded-For
            case 'ico_x_forwarded_for':
                $headers = $headers ?: self::httpGetHeaders();
                if (isset($headers['Ico-X-Forwarded-For'], $headers['X-Forwarded-Host'])) {
                    $ip_version = self::ipValidate($headers['Ico-X-Forwarded-For']);
                    if ($ip_version) {
                        $out = $ip_version === 'v6' && ! $v4_only ? self::ipV6Normalize(
                            $headers['Ico-X-Forwarded-For']
                        ) : $headers['Ico-X-Forwarded-For'];
                    }
                }
                break;

            // OVH
            case 'ovh':
                $headers = $headers ?: self::httpGetHeaders();
                if (isset($headers['X-Cdn-Any-Ip'], $headers['Remote-Ip'])) {
                    $ip_version = self::ipValidate($headers['Remote-Ip']);
                    if ($ip_version) {
                        $out = $ip_version === 'v6' && ! $v4_only ? self::ipV6Normalize(
                            $headers['Remote-Ip']
                        ) : $headers['Remote-Ip'];
                    }
                }
                break;

            // Incapsula proxy
            case 'incapsula':
                $headers = $headers ?: self::httpGetHeaders();
                if (isset($headers['Incap-Client-Ip'], $headers['X-Forwarded-For'])) {
                    $ip_version = self::ipValidate($headers['Incap-Client-Ip']);
                    if ($ip_version) {
                        $out = $ip_version === 'v6' && ! $v4_only ? self::ipV6Normalize(
                            $headers['Incap-Client-Ip']
                        ) : $headers['Incap-Client-Ip'];
                    }
                }
                break;

            // Incapsula proxy like "X-Clientside":"10.10.10.10:62967 -> 192.168.1.1:443"
            case 'clientside':
                $headers = $headers ?: self::httpGetHeaders();
                if (
                    isset($headers['X-Clientside'])
                    && (preg_match('/^([0-9a-f.:]+):\d+ -> ([0-9a-f.:]+):\d+$/', $headers['X-Clientside'], $matches)
                    && isset($matches[1]))
                ) {
                    $ip_version = self::ipValidate($matches[1]);
                    if ($ip_version) {
                        $out = $ip_version === 'v6' && ! $v4_only ? self::ipV6Normalize($matches[1]) : $matches[1];
                    }
                }
                break;

            // Remote addr
            case 'remote_addr':
                $remote_addr = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : null;
                if (!empty($remote_addr)) {
                    $ip_version = self::ipValidate($_SERVER['REMOTE_ADDR']);
                    if ($ip_version) {
                        $out = $ip_version === 'v6' && ! $v4_only ? self::ipV6Normalize(
                            $_SERVER['REMOTE_ADDR']
                        ) : $_SERVER['REMOTE_ADDR'];
                    }
                }
                break;

            // X-Forwarded-For
            case 'x_forwarded_for':
                $headers = $headers ?: self::httpGetHeaders();
                if (isset($headers['X-Forwarded-For'])) {
                    $tmp        = explode(',', trim($headers['X-Forwarded-For']));
                    $tmp        = trim($tmp[0]);
                    $ip_version = self::ipValidate($tmp);
                    if ($ip_version) {
                        $out = $ip_version === 'v6' && ! $v4_only ? self::ipV6Normalize($tmp) : $tmp;
                    }
                }
                break;

            // X-Real-Ip
            case 'x_real_ip':
                $headers = $headers ?: self::httpGetHeaders();
                if (isset($headers['X-Real-Ip'])) {
                    $tmp        = explode(",", trim($headers['X-Real-Ip']));
                    $tmp        = trim($tmp[0]);
                    $ip_version = self::ipValidate($tmp);
                    if ($ip_version) {
                        $out = $ip_version === 'v6' && ! $v4_only ? self::ipV6Normalize($tmp) : $tmp;
                    }
                }
                break;

            // Real
            // Getting real IP from REMOTE_ADDR or Cf_Connecting_Ip if set or from (X-Forwarded-For, X-Real-Ip) if REMOTE_ADDR is local.
            case 'real':
                // Detect IP type
                $out = self::ipGet('cloud_flare', $v4_only, $headers);
                $out = $out ?: self::ipGet('sucury', $v4_only, $headers);
                $out = $out ?: self::ipGet('gtranslate', $v4_only, $headers);
                $out = $out ?: self::ipGet('ezoic', $v4_only, $headers);
                $out = $out ?: self::ipGet('stackpath', $v4_only, $headers);
                $out = $out ?: self::ipGet('x_forwarded_by', $v4_only, $headers);
                $out = $out ?: self::ipGet('ico_x_forwarded_for', $v4_only, $headers);
                $out = $out ?: self::ipGet('ovh', $v4_only, $headers);
                $out = $out ?: self::ipGet('incapsula', $v4_only, $headers);
                $out = $out ?: self::ipGet('clientside', $v4_only, $headers);

                $ip_version = self::ipValidate($out);

                // Is private network
                if (
                    ! $out ||
                    (
                        is_string($ip_version) && (
                            self::ipIsPrivateNetwork($out, $ip_version) ||
                            (
                                $ip_version === self::ipValidate($_SERVER['SERVER_ADDR']) &&
                                self::ipMaskMatch($out, $_SERVER['SERVER_ADDR'] . '/24', $ip_version)
                            )
                        )
                    )
                ) {
                    //@todo Remove local IP from x-forwarded-for and x-real-ip
                    $out = $out ?: self::ipGet('x_forwarded_for', $v4_only, $headers);
                    $out = $out ?: self::ipGet('x_real_ip', $v4_only, $headers);
                }

                $out = $out ?: self::ipGet('remote_addr', $v4_only, $headers);

                break;

            default:
                $out = self::ipGet('real', $v4_only, $headers);
        }

        if ( is_string($out) ) {
            $ip_version = self::ipValidate($out);

            if ( ! $ip_version ) {
                $out = null;
            }

            if ( $ip_version === 'v6' && $v4_only ) {
                $out = null;
            }
        }

        return $out;
    }

    /**
     * Checks if the IP is in private range
     *
     * @param string $ip
     * @param string $ip_type
     *
     * @return bool
     */
    public static function ipIsPrivateNetwork($ip, $ip_type = 'v4')
    {
        return self::ipMaskMatch($ip, self::$private_networks[$ip_type], $ip_type);
    }

    /**
     * Check if the IP belong to mask.  Recursive.
     * Octet by octet for IPv4
     * Hextet by hextet for IPv6
     *
     * @param string $ip
     * @param string|array $cidr work to compare with
     * @param string $ip_type IPv6 or IPv4
     * @param int $xtet_count Recursive counter. Determs current part of address to check.
     *
     * @return bool
     * @psalm-suppress InvalidScalarArgument
     */
    public static function ipMaskMatch($ip, $cidr, $ip_type = 'v4', $xtet_count = 0)
    {
        if (is_array($cidr)) {
            foreach ($cidr as $curr_mask) {
                if (self::ipMaskMatch($ip, $curr_mask, $ip_type)) {
                    return true;
                }
            }

            return false;
        }

        if ( ! self::ipValidate($ip) || ! self::cidrValidate($cidr) ) {
            return false;
        }

        $xtet_base = ($ip_type === 'v4') ? 8 : 16;

        // Calculate mask
        $exploded = explode('/', $cidr);

        if ( ! isset($exploded[0], $exploded[1]) ) {
            return false;
        }

        $net_ip   = $exploded[0];
        $mask     = (int)$exploded[1];

        // Exit condition
        $xtet_end = ceil($mask / $xtet_base);
        if ($xtet_count == $xtet_end) {
            return true;
        }

        // Length of bits for comparison
        $mask = $mask - $xtet_base * $xtet_count >= $xtet_base ? $xtet_base : $mask - $xtet_base * $xtet_count;

        // Explode by octets/hextets from IP and Net
        $net_ip_xtets = explode($ip_type === 'v4' ? '.' : ':', $net_ip);
        $ip_xtets     = explode($ip_type === 'v4' ? '.' : ':', $ip);

        // Standartizing. Getting current octets/hextets. Adding leading zeros.
        $net_xtet = str_pad(
            decbin(
                ($ip_type === 'v4' && (int)$net_ip_xtets[$xtet_count]) ? $net_ip_xtets[$xtet_count] : @hexdec(
                    $net_ip_xtets[$xtet_count]
                )
            ),
            $xtet_base,
            0,
            STR_PAD_LEFT
        );
        $ip_xtet  = str_pad(
            decbin(
                ($ip_type === 'v4' && (int)$ip_xtets[$xtet_count]) ? $ip_xtets[$xtet_count] : @hexdec(
                    $ip_xtets[$xtet_count]
                )
            ),
            $xtet_base,
            0,
            STR_PAD_LEFT
        );

        // Comparing bit by bit
        for ($i = 0, $result = true; $mask != 0; $mask--, $i++) {
            if ($ip_xtet[$i] != $net_xtet[$i]) {
                $result = false;
                break;
            }
        }

        // Recursing. Moving to next octet/hextet.
        if ($result) {
            $result = self::ipMaskMatch($ip, $cidr, $ip_type, $xtet_count + 1);
        }

        return $result;
    }

    /**
     * Validating IPv4, IPv6
     *
     * @param string|null|false $ip
     *
     * @return string|bool
     */
    public static function ipValidate($ip)
    {
        if ( ! $ip ) { // NULL || FALSE || '' || so on...
            return false;
        }
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) && $ip != '0.0.0.0') { // IPv4
            return 'v4';
        }
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) && self::ipV6Reduce($ip) != '0::0') { // IPv6
            return 'v6';
        }

        return false; // Unknown
    }

    /**
     * Validate CIDR
     *
     * @param string $cidr expects string like 1.1.1.1/32
     *
     * @return bool
     */
    public static function cidrValidate($cidr)
    {
        $cidr = explode('/', $cidr);

        return isset($cidr[0], $cidr[1]) && self::ipValidate($cidr[0]) && preg_match('@\d{1,2}@', $cidr[1]);
    }

    /**
     * Expand IPv6
     *
     * @param string $ip
     *
     * @return string IPv6
     */
    public static function ipV6Normalize($ip)
    {
        $ip = trim($ip);
        // Searching for ::ffff:xx.xx.xx.xx patterns and turn it to IPv6
        if (preg_match('/^::ffff:([0-9]{1,3}\.?){4}$/', $ip)) {
            $ip = dechex((int)sprintf("%u", ip2long(substr($ip, 7))));
            $ip = '0:0:0:0:0:0:' . (strlen($ip) > 4 ? substr('abcde', 0, -4) : '0') . ':' . substr($ip, -4, 4);
            // Normalizing hextets number
        } elseif (strpos($ip, '::') !== false) {
            $ip = str_replace('::', str_repeat(':0', 8 - substr_count($ip, ':')) . ':', $ip);
            $ip = strpos($ip, ':') === 0 ? '0' . $ip : $ip;
            $ip = strpos(strrev($ip), ':') === 0 ? $ip . '0' : $ip;
        }
        // Simplifyng hextets
        if (preg_match('/:0(?=[a-z0-9]+)/', $ip)) {
            $ip = preg_replace('/:0(?=[a-z0-9]+)/', ':', strtolower($ip));
            $ip = self::ipV6Normalize($ip);
        }

        return $ip;
    }

    /**
     * Reduce IPv6
     *
     * @param string $ip
     *
     * @return string IPv6
     */
    public static function ipV6Reduce($ip)
    {
        if (strpos($ip, ':') !== false) {
            $ip = preg_replace('/:0{1,4}/', ':', $ip);
            $ip = preg_replace('/:{2,}/', '::', $ip);
            $ip = strpos($ip, '0') === 0 && substr($ip, 1) !== false ? substr($ip, 1) : $ip;
        }

        return $ip;
    }

    /**
     * Gets every HTTP_ headers from $_SERVER
     *
     * If Apache web server is missing then making
     * Patch for apache_request_headers()
     *
     * returns array
     */
    public static function httpGetHeaders()
    {
        // If headers already return them
        $headers = array();
        foreach ($_SERVER as $key => $val) {
            if (0 === stripos($key, 'http_')) {
                $server_key = preg_replace('/^http_/i', '', $key);
                $key_parts  = explode('_', $server_key);
                if (strlen($server_key) > 2) {
                    foreach ($key_parts as $part_index => $part) {
                        if ($part === '') {
                            continue;
                        }

                        $key_parts[$part_index] = function_exists('mb_strtolower') ? mb_strtolower(
                            $part
                        ) : strtolower(
                            $part
                        );
                        $key_parts[$part_index][0] = strtoupper($key_parts[$part_index][0]);
                    }
                    $server_key = implode('-', $key_parts);
                }
                $headers[$server_key] = $val;
            }
        }

        return $headers;
    }

    /**
     * Function convert from UTF8
     *
     * @param array|object|string $obj
     * @param string $data_codepage
     *
     * @return mixed (array|object|string)
     */
    public static function fromUTF8($obj, $data_codepage = null)
    {
        // Array || object
        if (is_array($obj) || is_object($obj)) {
            foreach ($obj as $_key => &$val) {
                $val = self::fromUTF8($val, $data_codepage);
            }
            unset($val);
            //String
        } else {
            if ($data_codepage !== null && preg_match('//u', $obj)) {
                if ( function_exists('mb_convert_encoding') ) {
                    $obj = mb_convert_encoding($obj, $data_codepage, 'UTF-8');
                } elseif (version_compare(phpversion(), '8.3', '<')) {
                    $obj = @utf8_decode($obj);
                }
            }
        }

        return $obj;
    }
}
