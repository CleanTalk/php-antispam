# CleanTalk php-antispam: Lightweight Spam Protection for PHP Apps
============

![example workflow](https://github.com/CleanTalk/php-antispam/actions/workflows/tests.yml/badge.svg)

[![Latest Stable Version](https://poser.pugx.org/cleantalk/php-antispam/v)](https://packagist.org/packages/cleantalk/php-antispam)

## Invisible spam protection: no CAPTCHA, puzzles, or math tests

_A PHP client for the CleanTalk anti-spam API_

If you find this project useful, please consider starring it on GitHub ⭐. It helps us improve and maintain the project.

#### Requirements

* PHP 5.6 or later
* cURL support

### How does it stop spam?

This PHP library provides invisible spam protection for websites, registration forms, and comment sections. The CleanTalk API is a CAPTCHA alternative that detects spam without interrupting your users.

When a user submits a form, the library securely sends the form data to CleanTalk's cloud servers for analysis. CleanTalk then returns a real-time verdict identifying the submission as legitimate or spam. Your application decides how to handle that verdict.

## CleanTalk vs CAPTCHA
| Feature             | CleanTalk Anti-Spam               | Traditional CAPTCHA                      |
|---------------------|-----------------------------------|------------------------------------------|
| User Interaction    | 100% invisible to users           | Requires solving puzzles or clicks       |
| Form Compatibility  | Works with any PHP form           | Often requires additional scripts        |
| Speed               | Instant cloud check               | Slower due to user interaction           |
| Accessibility       | No visual tests                   | Can be difficult for screen-reader users |

> CleanTalk is a **PHP spam filter** and **CAPTCHA-free alternative** that protects your forms without adding friction for users.

## Getting started

Setup takes only a few minutes.

### Step 1: install the SDK

Install the SDK with Composer:

```bash
composer require cleantalk/php-antispam
```

Alternatively, download the ZIP archive and extract it into your project directory.

### Step 2: configure your API key

First, copy your API key from your [CleanTalk dashboard](https://cleantalk.org/my/).

Make it available to PHP as an environment variable:

| Name | Value |
|---|---|
| `CLEANTALK_API_KEY` | Your CleanTalk API key |

On managed hosting, add it in the **Environment variables** or **Secrets** section of your hosting control panel, then restart the application if required.

If your application already loads a `.env` file, add:

```dotenv
CLEANTALK_API_KEY=your-api-key
```

PHP does not load `.env` files by itself; this option works only when your application or framework includes a dotenv loader. Do not put the API key in your PHP files or commit it to source control.

### Step 3: add the CleanTalk handler to your form handler

Add the handler to your PHP code:

```php linenums="1"
$api_key = getenv('CLEANTALK_API_KEY');
if (empty($api_key)) {
    throw new RuntimeException('CLEANTALK_API_KEY is not configured');
}

$email = $_POST['email']; // Get this value from your form.
$cleantalk_antispam = (new CleantalkAntispam($api_key))
    ->setEmail($email);
// Set additional parameters here.
$api_result = $cleantalk_antispam->handle();
```

See [additional configuration options](readme_additional.md) to select the form type and provide the sender name, message, IP address, and Bot Detector settings.

### Step 4: add the JavaScript library to your HTML template

The library collects frontend data used for bot detection.

```html
<script src="https://fd.cleantalk.org/ct-bot-detector-wrapper.js" defer></script>
```

Enable the event token in your PHP handler:

```php linenums="3"
...
// Set additional parameters here.
$cleantalk_antispam->setEventTokenEnabled(1);
...
```

### Step 5: handle the API verdict

For example, stop processing when CleanTalk identifies a submission as spam:

```php
if ($api_result && $api_result->allow === 0) {
    die('Blocked. Spam protection OK. Reason: ' . $api_result->comment);
    // Or add your own actions, logs, or messages.
}
```

### Step 6 (optional): troubleshoot the integration

To identify possible configuration problems, log the improvement suggestions after calling `handle()`:

```php
// Troubleshooting: log improvement suggestions.
error_log($cleantalk_antispam->whatsWrong(true));
```

The diagnostic output can contain personal data. Use this logging only while troubleshooting and store it in appropriately protected logs.

See the [complete form-handler example](https://github.com/CleanTalk/php-antispam/blob/dev/examples/form_with_handler/form_with_handler.php) for context.

### Step 7 (optional): get help

If you have questions, open a GitHub issue or contact us through our ticket system.

## Examples

* [API response description](https://github.com/CleanTalk/php-antispam/tree/dev/examples/api_response_description.md)
* [Form-handler example](https://github.com/CleanTalk/php-antispam/blob/dev/examples/form_with_handler/form_with_handler.php)

## Looking for a universal integration?

See [php-uni](https://github.com/CleanTalk/php-uni) for a universal solution for CMS platforms and custom websites.

### Websites that trust CleanTalk!

![CleanTalk Anti-Spam Rating](https://cleantalk.org/webpack/img/cleantalk_rating.png)

Learn more about CleanTalk as a [reCAPTCHA alternative](https://cleantalk.org/recaptcha-alternative).
