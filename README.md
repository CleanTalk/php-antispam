php-antispam
============

A PHP API for antispam service cleantalk.org. Invisible protection from spam, no captches, no puzzles, no animals and no math.

## How API stops spam?
API uses several simple tests to stop spammers.
  * Spam bots signatures.
  * Blacklists checks by Email, IP, web-sites domain names.
  * JavaScript availability.
  * Comment submit time.
  * Relevance test for the comment.

## How API works?
API sends a comment's text and several previous approved comments to the servers. Servers evaluates the relevance of the comment's text on the topic, tests on spam and finaly provides a solution - to publish or put on manual moderation of comments. If a comment is placed on manual moderation, the plugin adds to the text of a comment explaining the reason for the ban server publishing.

## Requirements

   * PHP 4.3 and above 
   * CURL support 

## SPAM test for text comment sample

```php
require_once (dirname(__FILE__) . '/cleantalk.class.php');

// Take params from config
$config_url = 'http://moderate.cleantalk.ru';
$auth_key = null; // Set CleanTalk auth key

// The facility in which to store the query parameters
$ct_request = new CleantalkRequest();

$ct_request->auth_key = $auth_key;
$ct_request->message = 'stop_word';
$ct_request->sender_email = 'stop_email@example.com';
$ct_request->sender_nickname = 'John Dow';
$ct_request->example = str_repeat('Just text ', 10);
$ct_request->agent = 'php-api';
$ct_request->sender_ip = '178.32.183.43';
$ct_request->js_on = 1; # Site visitor has JavaScript
$ct_request->submit_time = 12; # Seconds from start form filling till the form POST

$ct = new Cleantalk();
$ct->server_url = $config_url;

// Check
$ct_result = $ct->isAllowMessage($ct_request);

if ($ct_result->allow == 1) {
    echo 'Comment allowed. Reason ' . $ct_result->comment;
} else {
    echo 'Comment blocked. Reason ' . $ct_result->comment;
}
```

## API Response description
API returns PHP object:
  * allow (0|1) - allow to publish or not, in other words spam or ham
  * comment (string) - server comment for requests.
  * id (string MD5 HEX hash) - unique request idenifier.
  * errno (int) - error number. errno == 0 if requests successfull.
  * errtstr (string) - comment for error issue, errstr == null if requests successfull.
  * account_status - 0 account disabled, 1 account enabled, -1 unknown status.
  
