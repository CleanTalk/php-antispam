# Additional CleanTalk configuration

Configure the request after creating `CleantalkAntispam` and before calling `handle()`. The configuration methods return the same object, so they can be chained.

Pass the **values** of form fields to these methods, not their HTML field names. The constructor accepts the access key and, optionally, the sender email. The `$user_name_field`, `$message_field`, and `$type_form` constructor arguments are deprecated and not used: call the methods described below instead.

## Contact form example

Assume that `$email`, `$name`, `$subject`, and `$message` have already been read from the form and validated by your application.

```php
$api_result = (new CleantalkAntispam($api_key))
    ->useContactFormCheck()
    ->setEventTokenEnabled(1)
    ->setEmail($email)
    ->setNickName($name)
    ->setMessage($subject . ': ' . $message)
    ->handle();
```

`useContactFormCheck()` uses the [`check_message`](https://cleantalk.org/help/api-check-message) API method. It is intended for contact forms, comments, reviews, and other user-generated content.

## Registration form example

For registration, subscription, and similar forms without a message, use the [`check_newuser`](https://cleantalk.org/help/api-check-newuser) API method:

```php
$api_result = (new CleantalkAntispam($api_key))
    ->useRegistrationCheck()
    ->setEventTokenEnabled(1)
    ->setEmail($email)
    ->setNickName($name)
    ->handle();
```

## Sender and form data

| Method | API parameter | Description |
|---|---|---|
| `setEmail($email)` | `sender_email` | Sender email address. If not set, the library looks for an email address in `$_POST`. Passing the validated value explicitly is more reliable. |
| `setNickName($name)` | `sender_nickname` | Sender name or nickname. |
| `setMessage($text)` | `message` | Text to check: message body, subject, or other text fields. |
| `setIP($ip)` | `sender_ip` | Overrides the automatically detected IP address. Use it only when your application already knows the real visitor IP (for example, behind a trusted proxy). An invalid IP is ignored and a troubleshooting suggestion is added. |

## Check type

- `useContactFormCheck()` — the `check_message` method: forms with user-written text.
- `useRegistrationCheck()` — the `check_newuser` method: forms without such text.

If no type is selected, `handle()` uses `check_message` when the message is not empty and `check_newuser` otherwise. Selecting the type explicitly is recommended.

## Scripts on the form page

Print the library HTML code on the page with the form, passing **the same access key** as in the form handler:

```php
echo CleantalkAntispam::getFrontendHTMLCode($api_key);
```

The method outputs:

1. **Bot Detector** (`fd.cleantalk.org/ct-bot-detector-wrapper.js`), which adds an event token to the form data.
2. **JavaScript check script** (`ct-js-check.js`), which stores the hash for [offline protection](#offline-protection) in the `ct_js_check` cookie.

To show a warning to visitors without JavaScript, pass `true` as the second argument: `getFrontendHTMLCode($api_key, true)`.

> The legacy call `getFrontendHTMLCode(true)` without a key still works, but outputs only Bot Detector. Without the JavaScript check script, offline protection will block every visitor.

## Bot Detector and event token

### `setEventTokenEnabled(1)`

Required when `getFrontendHTMLCode()` is printed on the page. It tells the cloud that Bot Detector is installed. Do not call it for forms without Bot Detector.

### `setEventToken($event_token)`

The library normally reads the token from `$_POST['ct_bot_detector_event_token']`. If the form data arrives another way (for example, as JSON), pass the token explicitly:

```php
$cleantalk_antispam
    ->setEventToken($event_token)
    ->setEventTokenEnabled(1);
```

### `setDoBlockNoJSVisitor()`

By default, a missing token alone does not block the request. With this method, `handle()` immediately returns a blocking verdict when the token is missing or invalid, without sending a request to the cloud.

## Offline protection

If the CleanTalk cloud is unavailable, the library makes the decision itself based on a JavaScript check. Offline protection is always enabled.

**When it is used.** The cloud did not respond within `CLEANTALK_MODERATE_TIMEOUT` seconds, a connection error occurred, the response code was not HTTP 200, or the response was not valid JSON.

**How the decision is made.** If the `ct_js_check` cookie matches the expected hash, the request is allowed. If the cookie is missing or does not match, the request is blocked. In both cases the verdict has `offline = true`.

> **Behavior change.** Previously, all requests were allowed when the cloud was unavailable. Now they are blocked without a valid cookie, so the JavaScript check script must be set up.

### Constants

Define them with `define()` before using the library, in code that runs both when the form page is rendered and in the form handler: the hash must match in both places.

| Constant | Required | Description | Default |
|---|---|---|---|
| `CLEANTALK_ACCOUNT_EMAIL` | yes | CleanTalk account email, used in the hash. | `''` |
| `CLEANTALK_SALT` | yes | Secret string of at least 32 characters. Without it, the hash depends on the access key only. | `''` |
| `CLEANTALK_JS_URL` | if the library is outside the web root | Public URL of the directory containing `ct-js-check.js`. | auto-detected |
| `CLEANTALK_MODERATE_TIMEOUT` | no | Seconds to wait for the cloud. | `2` |
| `CLEANTALK_OFFLINE_MODE` | no | `true` — never contact the cloud. For testing and emergencies only. | `false` |

### Making `ct-js-check.js` reachable

If the library directory is inside the web root, the URL is detected automatically. If it is outside (for example, `vendor/` is above the public directory), choose one option:

- **serve the file with your own handler (recommended):**

  ```php
  // handler at /cleantalk/ct-js-check.js
  header('Content-Type: application/javascript');
  readfile('/path/to/php-antispam/js/ct-js-check.js');
  ```

  and set `define('CLEANTALK_JS_URL', '/cleantalk');`;

- **copy** `js/ct-js-check.js` into a public directory and set its URL in `CLEANTALK_JS_URL`. Copy the file again after every library update.

The library appends the file name and version to the URL itself: `/cleantalk/ct-js-check.js?version=4.4`.

### Testing

1. Temporarily enable `define('CLEANTALK_OFFLINE_MODE', true);`.
2. Submit the form with JavaScript enabled — the request must pass.
3. Disable JavaScript, delete the `ct_js_check` cookie, reload the page, and submit the form — the request must be blocked.
4. Remove `CLEANTALK_OFFLINE_MODE`.

## Verdict

| Field | Description |
|---|---|
| `allow` | `1` — allow, `0` — block. |
| `comment` | Reason for the decision. |
| `offline` | `true` if the decision was made locally, without the cloud. |
| `request_link` | Link to the request in the CleanTalk dashboard (online mode only). |
| `error` | Error that prevented the check (for example, an empty access key). |

## Automatically populated request data

| API parameter | Source |
|---|---|
| `sender_ip` | IP of the current HTTP request, unless set with `setIP()` |
| `event_token` | `$_POST['ct_bot_detector_event_token']`, unless set with `setEventToken()` |
| `js_on` | `1` when an event token is available, otherwise `0` |
| `agent` | Identifies the php-antispam library |
| `all_headers` | HTTP headers of the current request with sensitive headers removed |
| `sender_info` | Referrer, when available |
| `submit_time` | Not sent; not required when Bot Detector and `event_token_enabled` are used |

## Custom form data containers

`setCustomFormDataContainer($data_container)` only replaces the internal form data container. It does not map keys to email, name, or message, and does not refresh the email or token already collected in the constructor. To pass data, use `setEmail()`, `setNickName()`, `setMessage()`, and `setEventToken()`.

## Troubleshooting

Call `whatsWrong()` after `handle()` to see configuration suggestions, the prepared request data, and the verdict:

```php
$api_result = $cleantalk_antispam->handle();
error_log($cleantalk_antispam->whatsWrong(true));
```

Offline protection suggestions appear when `ct-js-check.js` is not reachable from the browser, when the decision was made without the cloud, or when the `ct_js_check` cookie did not arrive.

`getCleanTalkRequestData()` returns the decoded prepared request data for custom diagnostics.

> The diagnostic output contains email addresses, messages, IP addresses, and other personal data. Store it only in protected logs and remove temporary logging after troubleshooting.
