## API Response description
API returns (`$api_result`) PHP object:
  * allow (`bool/0|1`) – allow result to be published or not, in other words, spam(`0`) or ham(`1`).
  * comment (`string`) – server comment for requests.
  * id (`MD5 hash hex string`) – unique MD5 hash used as request identifier.
  * errno (`int`) - error number or `0` if the request is successful.
  * errstr (`string | null`) – comment for error issue or `null` if the request is successful.
  * account_status (`int`) – Status of the account:
    * `0` account disabled
    * `1` account enabled, 
    * `-1` unknown status.
