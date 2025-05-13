php-antispam
============
![example workflow](https://github.com/CleanTalk/php-antispam/actions/workflows/tests.yml/badge.svg)

[![Latest Stable Version](https://poser.pugx.org/cleantalk/php-antispam/v)](https://packagist.org/packages/cleantalk/php-antispam)

## The  Invisible protection from spam, no captches, no puzzles, no animals and no math.
_API for antispam service cleantalk.org_

#### Requirements
* PHP 5.6 and above 
* CURL support 

### How we stop spam?
Cleantalk catch your api request and provides analytical result to you.

You are free to do anything with spam, or just allow as to block spam (we will interrupt desirable request).


## Interesting? Let's make some settings (it will take few minutes)


### Step 1 - install our SDK (2 variants ability)

Through composer install **OR** through download zip arhive and unzip it to root directory (with your index.php)
```php
composer require cleantalk/php-antispam
```


### Step 2 - add CleantalkAntispam handler (middleware/interception) to your form handler (action)

```php
$apikey = ''; // get it here cleantalk.org (free trial)
$email_field = $_POST['email']; // get it from your form
$cleantalk_antispam = new CleantalkAntispam($apikey, $email_field);
$api_result = $cleantalk_antispam->handle();
```

### Step 2.1 - add js lib to your html template
```html
<script src="https://moderate.cleantalk.org/ct-bot-detector-wrapper.js"></script>
```
_Need for gathering frontend data._

### Step 3 - do whatever you want with cloud result
For example add die block for spam.
```php
if ($api_result && $api_result->allow === 0) {
    die('Blocked. Spam protection OK. Reason: ' . $api_result->comment);
    // or make your own actions/logs/messages ...
}
```

### Step 4 (not required) - we prepare for you special troubleshooting method
To find possible problems, just add follow snippet after getVerdict method.
```php
// TROUBLESHOOTING: logging the suggestions
error_log($cleantalk_antispam->whatsWrong(true));
```
In [example file](https://github.com/CleanTalk/php-antispam/blob/dev/examples/form_with_handler/form_with_handler.php) you can see context.

### Step 5 (not required) - if you have any question, please, feel free to ask it in issue here or in our tiket system

## Examples
- [api response description](https://github.com/CleanTalk/php-antispam/tree/dev/examples/api_response_description.md)
- [example with form handler](https://github.com/CleanTalk/php-antispam/blob/dev/examples/form_with_handler/form_with_handler.php)

  
## Don't want to deal with all this?
Universal solution for any CMS or custom website: https://github.com/CleanTalk/php-uni  
