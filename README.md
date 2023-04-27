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

You can unpack the archive with the plugin to the root of the site or install it using the composer

```php
composer require cleantalk/php-antispam
```
   
### Sample SPAM test for text comment and user signup

```php
<?php
session_start();

$apikey = 'your_cleantalk_api_key';
$email_field = 'name_email_form_field';
$user_name_field = 'name_user_name_form_field';
$message_field = 'name_message_form_field';
$type_form = 'contact'; // use 'signup' for user signup form

// if downloaded, unzip and include the app:
require_once 'php-antispam/cleantalk-antispam.php';
// if install the app by composer package:
use Cleantalk\CleantalkAntispam;

//require_once "lib/cleantalk-php-patch.php"; -- PHP-FPM

$cleantalk_antispam = new CleantalkAntispam($apikey, $email_field, $user_name_field, $message_field, $type_form);
$cleantalk_antispam->handle();
?>

<form method="post">
    <label for="login">Login:</label>
    <input type="text" name="name_user_name_form_field" id="login" />
    <br />
    <label for="email">Email:</label>
    <input type="text" name="name_email_form_field" id="email" value="" />
    <br />
    <label for="message">Message:</label>
    <textarea name="name_message_form_field" id="message"></textarea>
    <br />
    <input type="submit" />
</form>

<?php $cleantalk_antispam->frontendScript(); ?>
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
