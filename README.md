# CleanTalk php-antispam: Lightweight Spam Protection for PHP Apps
============
![example workflow](https://github.com/CleanTalk/php-antispam/actions/workflows/tests.yml/badge.svg)

[![Latest Stable Version](https://poser.pugx.org/cleantalk/php-antispam/v)](https://packagist.org/packages/cleantalk/php-antispam)

## The Invisible protection from spam, no captcha, no recaptcha, no puzzles, no math captcha.
_API for antispam service cleantalk.org_

#### Requirements
* PHP 5.6 and above 
* CURL support 

### How we stop spam?
PHP Anti-Spam library providing invisible spam protection for your websites, registration forms, and comment sections. CleanTalk API offers an effective CAPTCHA alternative that silently blocks spam without interrupting your users' experience.

When users submit forms on your website form, the form data is securely sent to CleanTalk’s cloud servers. CleanTalk analyzes submissions using advanced heuristics. CleanTalk then returns a real-time verdict— legitimate requests or spam.

You are free to do anything with spam, or just allow as to block spam (we will interrupt desirable request).

## CleanTalk vs CAPTCHA
| Feature             | CleanTalk Anti-Spam               | Traditional CAPTCHA                  |
|---------------------|-----------------------------------|--------------------------------------|
| User Interaction    | 100% invisible to users           | Requires solving puzzles or clicks   |
| Form Compatibility  | Works with any PHP form           | Often requires additional scripts    |
| Speed               | Instant cloud check               | Slower due to user interaction       |
| Accessibility       | Fully accessible, no visual tests | Often inaccessible to screen readers |

>  CleanTalk is a **PHP spam filter** and a **captcha-free alternative** that boosts UX and protects your forms with zero friction.

## Interesting? Let's make some settings (it will take few minutes)


### Step 1 - install our SDK (2 variants ability)

Through composer install **OR** through download zip arhive and unzip it to root directory (with your index.php)
```php
composer require cleantalk/php-antispam
```


### Step 2 - add CleantalkAntispam handler (middleware/interception) to your form handler (action)

```php linenums="1"
$apikey = ''; // get it here cleantalk.org (free trial)
$email_field = $_POST['email']; // get it from your form
$cleantalk_antispam = new CleantalkAntispam($apikey, $email_field);
// Additional parameters here
$api_result = $cleantalk_antispam->handle();
```

### Step 2.1 - add js lib to your html template
_Need for gathering frontend data._
```html
<script src="https://moderate.cleantalk.org/ct-bot-detector-wrapper.js" defer></script>
```
and do not forget to add additional parameter to the request
```php linenums="3"
...
// Additional parameters here
$cleantalk_antispam->setEventTokenEnabled(1);
...
```

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
