<?php
require_once '../../../php-antispam/cleantalk-antispam.php';

use CleanTalk\CleantalkAntispam;

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Contact Form</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            line-height: 1.6;
        }
        .form-group {
            margin-bottom: 15px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }
        input[type="text"],
        input[type="email"],
        textarea {
            width: 100%;
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 4px;
            box-sizing: border-box;
        }
        button {
            background-color: #4CAF50;
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
        }
        button:hover {
            background-color: #45a049;
        }
        .message {
            padding: 10px;
            margin: 10px 0;
            border-radius: 4px;
        }
        .success {
            background-color: #dff0d8;
            color: #3c763d;
        }
        .error {
            background-color: #f2dede;
            color: #a94442;
        }
    </style>

    <!-- CLEANTALK ANTISPAM -->
    <script src="https://fd.cleantalk.org/ct-bot-detector-wrapper.js"></script>
    <!-- END OF CLEANTALK ANTISPAM -->
</head>
<body>
    <h1>Contact Us</h1>
    
    <?php
    $statusMessage = '';
    $messageType = '';

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $name = filter_input(INPUT_POST, 'name', FILTER_SANITIZE_STRING);
        $email = filter_input(INPUT_POST, 'email', FILTER_SANITIZE_EMAIL);
        $message = filter_input(INPUT_POST, 'message', FILTER_SANITIZE_STRING);

        if (empty($name) || empty($email) || empty($message)) {
            $statusMessage = 'Please fill in all fields.';
            $messageType = 'error';
        }

        if ($messageType !== 'error' && !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $statusMessage = 'Please enter a valid email address.';
            $messageType = 'error';
        }

        if ($messageType !== 'error' && !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $statusMessage = 'Please enter a valid email address.';
            $messageType = 'error';
        }

        // HANDLE CLEANTALK ANTISPAM
        if ($messageType !== 'error') {
            $apikey = ''; // get it here cleantalk.org (free trial)
            $email_field = $email; // get it from your form
            $cleantalk_antispam = new CleantalkAntispam($apikey, $email_field);
            $api_result = $cleantalk_antispam->handle();
            if ($api_result->allow === 0) {
                $statusMessage = 'Spam detected - ' . $api_result->comment;
                $messageType = 'error';
            }

            // TROUBLESHOOTING: logging the suggestions
            error_log($cleantalk_antispam->whatsWrong(true));
        }
        // END OF HANDLE CLEANTALK ANTISPAM

        if ($messageType !== 'error') {
            $logEntry = date('Y-m-d H:i:s') . " | Name: $name | Email: $email | Message: $message\n";
            if (file_put_contents('./contacts.log', $logEntry, FILE_APPEND)) {
                $statusMessage = 'Thank you for your message! We will get back to you soon.';
                $messageType = 'success';
                $name = $email = $message = ''; // Clear form data after successful submission
            }
        }
    }
    ?>

    <?php if ($statusMessage) : ?>
        <div class="message <?php echo $messageType; ?>">
            <?php echo htmlspecialchars($statusMessage); ?>
        </div>
    <?php endif; ?>

    <form method="POST" action="">
        <div class="form-group">
            <label for="name">Name:</label>
            <input type="text" id="name" name="name" value="<?php echo isset($name) ? htmlspecialchars($name) : ''; ?>" required>
        </div>

        <div class="form-group">
            <label for="email">Email:</label>
            <input type="email" id="email" name="email" value="<?php echo isset($email) ? htmlspecialchars($email) : ''; ?>" required>
        </div>

        <div class="form-group">
            <label for="message">Message:</label>
            <textarea id="message" name="message" rows="5" required><?php echo isset($message) ? htmlspecialchars($message) : ''; ?></textarea>
        </div>

        <button type="submit">Send Message</button>
    </form>
</body>
</html>
