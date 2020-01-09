php-antispam
============
[![Build Status](https://travis-ci.org/CleanTalk/php-antispam.svg)](https://travis-ci.org/CleanTalk/php-antispam)

[![Latest Stable Version](https://poser.pugx.org/cleantalk/php-antispam/v/stable.svg)](https://packagist.org/packages/cleantalk/php-antispam)

A PHP API for antispam service cleantalk.org. Invisible protection from spam, no captches, no puzzles, no animals and no math.

## How API stops spam?
API uses several simple tests to stop spammers.
  * Spam bots signatures.
  * Blacklists checks by Email, IP, web-sites domain names.
  * JavaScript availability.
  * Relevance test for the comment.

## How API works?
API sends a comment's text and several previous approved comments to the servers. Servers evaluates the relevance of the comment's text on the topic, tests on spam and finaly provides a solution - to publish or put on manual moderation of comments. If a comment is placed on manual moderation, the plugin adds to the text of a comment explaining the reason for the ban server publishing.

## Requirements

   * PHP 5.6 and above 
   * CURL support 


## Sample SPAM test for user signup

```php
<?php

session_start();

//require_once "vendor/autoload.php"; -- Composer

require_once "lib/Cleantalk.php";
require_once "lib/CleantalkHelper.php";
require_once "lib/CleantalkRequest.php";

use lib\Cleantalk;
use lib\CleantalkRequest;

// Take params from config
$config_url = 'http://moderate.cleantalk.org/api2.0/';
$auth_key = 'enter key'; // Set Cleantalk auth key

if (count($_POST)) {
    $sender_nickname = 'John Dow';
    if (isset($_POST['login']) && $_POST['login'] != '')
        $sender_nickname = $_POST['login'];

    $sender_email = 'stop_email@example.com';
    if (isset($_POST['email']) && $_POST['email'] != '')
        $sender_email = $_POST['email'];

    $sender_ip = null;
    if (isset($_SERVER['REMOTE_ADDR']))
        $sender_ip = $_SERVER['REMOTE_ADDR'];

    $js_on = 0; 
    if (isset($_POST['js_on']) && $_POST['js_on'] == date("Y"))
        $js_on = 1; 

    // The facility in which to store the query parameters
    $ct_request = new CleantalkRequest();

    $ct_request->auth_key = $auth_key;
    $ct_request->agent = 'php-api';
    $ct_request->sender_email = $sender_email; 
    $ct_request->sender_ip = $sender_ip; 
    $ct_request->sender_nickname = $sender_nickname; 
    $ct_request->js_on = $js_on;
    $ct_request->submit_time = time() - (int) $_SESSION['ct_submit_time'];

    $ct = new Cleantalk();
    $ct->server_url = $config_url; 

    // Check
    $ct_result = $ct->isAllowUser($ct_request);

    if ($ct_result->allow == 1) {
        echo 'User allowed. Reason ' . $ct_result->comment;
    } else {
        echo 'User forbidden. Reason ' . $ct_result->comment;
    }
    echo '<br /><br />';
}
else
{
    $_SESSION['ct_submit_time'] = time();
}
?>

<form method="post">
    <label for="login">Login:<label>
    <input type="text" name="login" id="login" />
    <br />
    <label for="email">Email:<label>
    <input type="text" name="email" id="email" value="" />
    <br />
    <input type="hidden" name="js_on" id="js_on" value="0" />
    <input type="submit" />
</form>

<script type="text/javascript">
    var date = new Date();

    document.getElementById("js_on").value = date.getFullYear(); 
</script>
```

## Sample SPAM test for text comment

```php
<?php

session_start();

//require_once "vendor/autoload.php"; -- Composer

require_once "lib/Cleantalk.php";
require_once "lib/CleantalkHelper.php";
require_once "lib/CleantalkRequest.php";

use lib\Cleantalk;
use lib\CleantalkRequest;

// Take params from config
$config_url = 'http://moderate.cleantalk.org/api2.0/';
$auth_key = 'enter key'; // Set Cleantalk auth key

if (count($_POST)) {
    $sender_nickname = 'John Dow';
    if (isset($_POST['login']) && $_POST['login'] != '')
        $sender_nickname = $_POST['login'];

    $sender_email = 'stop_email@example.com';
    if (isset($_POST['email']) && $_POST['email'] != '')
        $sender_email = $_POST['email'];

    $sender_ip = null;
    if (isset($_SERVER['REMOTE_ADDR']))
        $sender_ip = $_SERVER['REMOTE_ADDR'];

    $js_on = 0; 
    if (isset($_POST['js_on']) && $_POST['js_on'] == date("Y"))
        $js_on = 1; 
    
    $message = null; 
    if (isset($_POST['message']) && $_POST['message'] != '')
        $message = $_POST['message']; 

    // The facility in which to store the query parameters
    $ct_request = new CleantalkRequest();

    $ct_request->auth_key = $auth_key;
    $ct_request->agent = 'php-api';
    $ct_request->sender_email = $sender_email; 
    $ct_request->sender_ip = $sender_ip; 
    $ct_request->sender_nickname = $sender_nickname; 
    $ct_request->js_on = $js_on;
    $ct_request->message = $message;
    $ct_request->submit_time = time() - (int) $_SESSION['ct_submit_time'];

    $ct = new Cleantalk();
    $ct->server_url = $config_url; 

    // Check
    $ct_result = $ct->isAllowMessage($ct_request);

    if ($ct_result->allow == 1) {
        echo 'Message allowed. Reason ' . $ct_result->comment;
    } else {
        echo 'Message forbidden. Reason ' . $ct_result->comment;
    }
    echo '<br /><br />';
}
else
{
    $_SESSION['ct_submit_time'] = time();
}
?>

<form method="post">
    <label for="login">Login:<label>
    <input type="text" name="login" id="login" />
    <br />
    <label for="email">Email:<label>
    <input type="text" name="email" id="email" value="" />
    <br />
    <label for="message">Message:<label>
    <textarea name="message" id="message"></textarea>
    <br />
    <input type="hidden" name="js_on" id="js_on" value="0" />
    <input type="submit" />
</form>

<script type="text/javascript">
    var date = new Date();

    document.getElementById("js_on").value = date.getFullYear(); 
</script>
```


## API Response description
API returns PHP object:
  * allow (0|1) - allow to publish or not, in other words spam or ham
  * comment (string) - server comment for requests.
  * id (string MD5 HEX hash) - unique request idenifier.
  * errno (int) - error number. errno == 0 if requests successfull.
  * errstr (string) - comment for error issue, errstr == null if requests successfull.
  * account_status - 0 account disabled, 1 account enabled, -1 unknown status.
  
## Don't want to deal with all this?
Universal solution for any CMS or custom website: https://github.com/CleanTalk/php-uni  
