## API Response description
API returns (`$api_result`) PHP object:
  * allow (0|1) - allow to publish or not, in other words spam or ham
  * comment (string) - server comment for requests.
  * id (string MD5 HEX hash) - unique request idenifier.
  * errno (int) - error number. errno == 0 if requests successfull.
  * errstr (string) - comment for error issue, errstr == null if requests successfull.
  * account_status - 0 account disabled, 1 account enabled, -1 unknown status.
