<?php
session_start();

$apikey = '';
$email_field = 'name_email_form_field';
$user_name_field = 'name_user_name_form_field';
$message_field = 'name_message_form_field';
$type_form = 'contact'; // use 'signup' for user signup form

// if downloaded, unzip and include the app, take your own relative path:
require_once '../../cleantalk-antispam.php';
// if install the app by composer package:
use Cleantalk\CleantalkAntispam;

//require_once "lib/cleantalk-php-patch.php"; -- PHP-FPM

$cleantalk_antispam = new CleantalkAntispam($apikey, $email_field, $user_name_field, $message_field, $type_form);
$api_result = $cleantalk_antispam->handle();
if ($api_result) { // the check fired
    if ($api_result->account_status !== 1) {
        // something wrong with your key or license, to know why read $api_result->codes
        echo 'Allowed. Spam protection disabled.'; // or do nothing
    } else {
        if ($api_result->allow === 1) {
            echo 'Allowed. Spam protection OK.'; // or do nothing
        } else {
            die('Blocked. Spam protection OK. Reason: ' . $api_result->comment); // or make your own handler
        }
    }
}
// your further code flow here
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
