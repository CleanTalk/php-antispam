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

Use the access-key form of `getFrontendHTMLCode()` for offline protection so the cookie matches the value expected by the form handler.

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

See [Offline mode in the README](README.md#step-6-optional-offline-mode) for setup and limitations. The local check compares the `ct_js_check` cookie with the expected hash; it is basic protection, not a replacement for cloud spam analysis.
To activate additional cloud check after offline protection passed, just call additional method `setForcedOfflineCloudCheckEnabled()`

```php
$result = (new CleantalkAntispam($api_key))
    ->useContactFormCheck()
    ->setEmail($email)
    ->setNickName($name)
    ->setMessage($message)
    ->setForcedOfflineCloudCheckEnabled() // <- this is the necessary method call
    ->handle();
```

### Checking with the cloud in forced offline mode

With offline mode enabled as described in the README, the library normally makes only the local JavaScript check. To additionally check locally allowed submissions with the cloud, enable the check on the `CleantalkAntispam` instance:

```php
$cleantalk_antispam = (new CleantalkAntispam($api_key))
    ->setMessage($message)
    ->setForcedOfflineCloudCheckEnabled();
$api_result = $cleantalk_antispam->handle();
```

This setting has an effect only in forced offline mode and only when the JavaScript check passes. Locally blocked submissions are not sent to the cloud. The cloud request's `sender_info` includes `ct_offline_mode: 1` and `ct_offline_allow: 1`, identifying it as a request that passed the local check.

A successful cloud response becomes the final verdict, so a cloud rejection blocks the request. In this case, `offline` is `false`, and `request_link` is populated when the cloud returns a request ID. If the cloud is unavailable, the request keeps its positive offline verdict with `offline = true`. The default timeout for this cloud check is 2 seconds.

Without this method call, forced offline mode continues to make only the local JavaScript check. Pass `false` to `setForcedOfflineCloudCheckEnabled(false)` to disable the additional check.

### Testing

1. Enable offline mode as described in the README, without the additional cloud check.
2. Submit the form with JavaScript enabled — the request must pass.
3. Disable JavaScript, delete the `ct_js_check` cookie, reload the page, and submit the form — the request must be blocked.
4. Restore the desired mode after testing.

## Verdict

| Field | Description |
|---|---|
| `allow` | `1` — allow, `0` — block. |
| `comment` | Reason for the decision. |
| `offline` | `true` if the decision was made locally, without the cloud. |
| `request_link` | Link to the request in the CleanTalk dashboard (online mode only). |
| `error` | Error that prevented the check (for example, an empty access key), or the cloud error when offline protection is not enabled. |

## Automatically populated request data

| API parameter | Source |
|---|---|
| `sender_ip` | IP of the current HTTP request, unless set with `setIP()` |
| `event_token` | `$_POST['ct_bot_detector_event_token']`, unless set with `setEventToken()` |
| `js_on` | `1` when an event token is available, otherwise `0` |
| `agent` | Identifies the php-antispam library |
| `all_headers` | HTTP headers of the current request with sensitive headers removed |
| `sender_info` | Referrer, when available; `ct_offline_mode: 1` and `ct_offline_allow: 1` for the additional cloud check after a local allow |
| `submit_time` | Not sent; not required when Bot Detector and `event_token_enabled` are used |

## Custom form data containers

`setCustomFormDataContainer($data_container)` only replaces the internal form data container. It does not map keys to email, name, or message, and does not refresh the email or token already collected in the constructor. To pass data, use `setEmail()`, `setNickName()`, `setMessage()`, and `setEventToken()`.

## Troubleshooting

Call `whatsWrong()` after `handle()` to see configuration suggestions, the prepared request data, and the verdict:

```php
$api_result = $cleantalk_antispam->handle();
error_log($cleantalk_antispam->whatsWrong(true));
```

Offline protection suggestions appear when the protection is not enabled, when `ct-js-check.js` is not reachable from the browser, when the decision was made without the cloud, or when the `ct_js_check` cookie did not arrive.

`getCleanTalkRequestData()` returns the decoded prepared request data for custom diagnostics.

> The diagnostic output contains email addresses, messages, IP addresses, and other personal data. Store it only in protected logs and remove temporary logging after troubleshooting.
