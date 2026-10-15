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

## 1. Installation

```bash
composer require cleantalk/php-antispam
```

Without Composer: extract the library archive and include `require_once '/path/to/php-antispam/cleantalk-antispam.php';`.

## 2. Constants

Define them in a shared settings file that is loaded **both on the form page and in the form handler**: the JavaScript check hash must match in both places.

```php
define('CLEANTALK_ACCOUNT_EMAIL', 'you@example.com');                  // required: CleanTalk account email
define('CLEANTALK_SALT', 'f3c9a1e07b2d4c8e9a6b5d0f1e2c3a4b');          // required: secret string, at least 32 characters
// define('CLEANTALK_JS_URL', '/cleantalk');                           // if the library is outside the web root (see step 4)
// define('CLEANTALK_MODERATE_TIMEOUT', 2);                            // cloud timeout, seconds (default 2 sec)
// define('CLEANTALK_OFFLINE_MODE', true);                             // testing only: never contact the cloud
```

## 3. Form page

Print the library scripts before the form or in `<head>`. Use the same access key as in the form handler.

```php
<?php echo \CleanTalk\CleantalkAntispam::getFrontendHTMLCode($apikey); ?>
<form method="post" action="/contact-handler.php">
    <input name="name">
    <input name="email" type="email">
    <textarea name="message"></textarea>
    <button type="submit">Send</button>
</form>
```

## 4. Making the JS file reachable

The browser must load `js/ct-js-check.js` from the library directory. If the directory is inside the web root, nothing needs to be done. If it is outside, choose one option.

**Option A (recommended): serve the file with your own handler** at `/cleantalk/ct-js-check.js`. This way the file always matches the installed library version.

```php
header('Content-Type: application/javascript');
readfile('/path/to/php-antispam/js/ct-js-check.js');
```

```php
define('CLEANTALK_JS_URL', '/cleantalk');
```

**Option B: copy the file** into a public directory, for example `/assets/cleantalk/`, and set `define('CLEANTALK_JS_URL', '/assets/cleantalk');`. Copy the file again after every library update.

## 5. Form handler

Check the data **before** saving it or sending an email:

```php
use CleanTalk\CleantalkAntispam;

$cleantalk = new CleantalkAntispam($apikey, $_POST['email']);
$result = $cleantalk
    ->setEventTokenEnabled(1)          // required: Bot Detector is included via getFrontendHTMLCode()
    ->setNickName($_POST['name'])      // user name, if available
    ->setMessage($_POST['message'])    // message text, if available
    ->useContactFormCheck()            // for registration forms: ->useRegistrationCheck()
    ->handle();

if (!$result->allow) {
    // Blocked: do not save the data, show $result->comment
}
```

`$result->offline` is `true` when the decision was made without the cloud.

## 6. Testing

1. Open the form page. In DevTools, make sure `ct-js-check.js` loads with status 200 and the `ct_js_check` cookie is set.
2. Temporarily add `define('CLEANTALK_OFFLINE_MODE', true);`.
   - With JavaScript enabled, the form must be **submitted**.
   - With JavaScript disabled and the cookie deleted, the form must be **blocked**.
3. Remove `CLEANTALK_OFFLINE_MODE`.

## Examples

* [API response description](https://github.com/CleanTalk/php-antispam/tree/dev/examples/api_response_description.md)
* [Form-handler example](https://github.com/CleanTalk/php-antispam/blob/dev/examples/form_with_handler/form_with_handler.php)

## Looking for a universal integration?

See [php-uni](https://github.com/CleanTalk/php-uni) for a universal solution for CMS platforms and custom websites.

## Related projects by CleanTalk

- [php-anticrawler](https://github.com/CleanTalk/php-anticrawler) - PHP library that blocks scrapers, SEO crawlers and bad bots by User-Agent, IP block lists and allow lists, with no captcha for real visitors. A good companion to this SDK when bots hit your pages, not only your forms.
- [anti-ddos-lite](https://github.com/CleanTalk/anti-ddos-lite) - small PHP app that stops HTTP flood and DDoS-like traffic with a JavaScript check.

### Websites that trust CleanTalk!

![CleanTalk Anti-Spam Rating](https://cleantalk.org/webpack/img/cleantalk_rating.png)

Learn more about CleanTalk as a [reCAPTCHA alternative](https://cleantalk.org/recaptcha-alternative).
