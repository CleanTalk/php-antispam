# Additional CleanTalk configuration

Configure the request after creating `CleantalkAntispam` and before calling `handle()`. The configuration methods return the same object, so they can be chained.

Pass actual form values to these methods, not HTML field names. The current constructor uses the access key and the optional second argument as an email address value. The legacy `$user_name_field`, `$message_field`, and `$type_form` constructor arguments are not used by the current implementation. Use the explicit setters below because they make every value sent to CleanTalk clear.

## Contact form example

Assume that `$email`, `$name`, `$subject`, and `$message` contain values that your application has already read and validated.

```php
$cleantalk_antispam = (new CleantalkAntispam($api_key))
    ->useContactFormCheck()
    ->setEmail($email)
    ->setNickName($name)
    ->setMessage($subject . ': ' . $message);

$api_result = $cleantalk_antispam->handle();
```

`useContactFormCheck()` uses the CleanTalk [`check_message`](https://cleantalk.org/help/api-check-message) API method. CleanTalk uses this method for contact forms and other user-generated content, including comments and reviews. The library does not send a separate contact-form subtype in the API request.

## Registration form example

Use the registration check for sign-up, subscription, or similar forms that do not contain a user-written message. See the CleanTalk [`check_newuser`](https://cleantalk.org/help/api-check-newuser) API documentation for the underlying request method.

```php
$cleantalk_antispam = (new CleantalkAntispam($api_key))
    ->useRegistrationCheck()
    ->setEmail($email)
    ->setNickName($name);

$api_result = $cleantalk_antispam->handle();
```

## Sender and form data

### `setEmail($email)`

Sets the sender email address. It is sent to the CleanTalk API as `sender_email`.

```php
$cleantalk_antispam->setEmail($email);
```

If no email is provided explicitly, the library attempts to find an email address in `$_POST`. Explicitly passing the validated email value is more reliable.

### `setNickName($nickname)`

Sets the sender name or nickname. It is sent as `sender_nickname` and allows CleanTalk to check the name for spam patterns.

```php
$cleantalk_antispam->setNickName($name);
```

### `setMessage($message)`

Sets the user-generated content to check. It is sent as `message` and can contain the message body, subject, or other relevant text fields.

```php
$cleantalk_antispam->setMessage($subject . ': ' . $message);
```

### `setIP($ip)`

Overrides the automatically detected sender IP address. Use it only when the application has already determined the original visitor IP, for example behind a trusted proxy.

```php
$cleantalk_antispam->setIP($visitor_ip);
```

If the supplied value is not a valid IP address, the library keeps the IP detected from the current request and adds a troubleshooting suggestion.

## Check type

### `useContactFormCheck()`

Selects the `check_message` API method. Use it for contact forms, comments, reviews, support requests, and other forms containing user-generated text.

```php
$cleantalk_antispam->useContactFormCheck();
```

### `useRegistrationCheck()`

Selects the `check_newuser` API method. Use it for registrations, subscriptions, and forms where there is no user-written message to inspect.

```php
$cleantalk_antispam->useRegistrationCheck();
```

If neither method is selected, `handle()` chooses `check_message` when a non-empty message has been set and `check_newuser` otherwise. Selecting the intended check explicitly is recommended.

## Bot Detector and event token

Add the Bot Detector script to the HTML page containing the form:

```html
<script src="https://fd.cleantalk.org/ct-bot-detector-wrapper.js" defer></script>
```

### `setEventTokenEnabled(1)`

When the Bot Detector script is installed for the form, enable event-token processing in the PHP request:

```php
$cleantalk_antispam->setEventTokenEnabled(1);
```

Do not set this flag for forms that do not use Bot Detector.

### `setEventToken($event_token)`

The library normally reads the generated token from `$_POST['ct_bot_detector_event_token']`. If the form data is received another way, such as a decoded JSON request, pass the token explicitly:

```php
$cleantalk_antispam
    ->setEventToken($event_token)
    ->setEventTokenEnabled(1);
```

### `setDoBlockNoJSVisitor()`

By default, the library does not locally block a visitor only because a valid event token is missing. Call this method if your application deliberately requires JavaScript and should reject requests without a valid token.

```php
$cleantalk_antispam->setDoBlockNoJSVisitor();
```

With this option enabled, `handle()` returns a blocked verdict without sending an API request when the event token is absent or invalid.

## Automatically populated request data

The library also prepares these values automatically:

| API parameter | Source |
|---|---|
| `sender_ip` | Detected from the current HTTP request unless overridden with `setIP()` |
| `event_token` | Read from `$_POST['ct_bot_detector_event_token']` unless set with `setEventToken()` |
| `js_on` | Set to `1` when an event token is available, otherwise `0` |
| `agent` | Identifies the php-antispam library |
| `all_headers` | Built from the current HTTP headers after sensitive headers are removed |
| `sender_info` | Includes the current referrer when available |
| `submit_time` | Not sent by the current library; CleanTalk does not require it when Bot Detector and `event_token_enabled` are used |

## Frontend HTML helper

`CleantalkAntispam::getFrontendHTMLCode()` returns the Bot Detector script tag. Pass `true` to also include a warning for visitors who have disabled JavaScript.

```php
echo CleantalkAntispam::getFrontendHTMLCode(true);
```

## Custom form data containers

### `setCustomFormDataContainer($data_container)`

The current implementation only replaces the internal form data container. It does not map custom keys to email, nickname, or message, and it does not refresh the email or event token that were collected during construction. Do not use this method for field mapping; pass the required values explicitly with `setEmail()`, `setNickName()`, `setMessage()`, and `setEventToken()`.

## Troubleshooting

Call `whatsWrong()` after `handle()` to inspect improvement suggestions, the prepared request data, and the verdict:

```php
$api_result = $cleantalk_antispam->handle();
error_log($cleantalk_antispam->whatsWrong(true));
```

After `handle()` has prepared a request, `getCleanTalkRequestData()` returns its decoded data for custom diagnostics:

```php
$request_data = $cleantalk_antispam->getCleanTalkRequestData();
```

The diagnostic output can contain email addresses, messages, IP addresses, and other personal data. Store it only in appropriately protected logs and remove temporary diagnostic logging when troubleshooting is complete.
