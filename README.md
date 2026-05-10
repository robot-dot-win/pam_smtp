## DESCRIPTION
pam_smtp is a Linux PAM module which provides a way to authenticate users against an SMTP server.

On success it returns PAM_SUCCESS, otherwise it returns PAM_AUTH_ERR, PAM_SERVICE_ERR, PAM_BUF_ERR or PAM_PERM_DENIED.

No credentials are awarded by this module.
## BUILD
The source program is a single C++17(and newer) file.

Requires: pam-devel, libcurl-devel

```bash
$ g++ -O2 pam_smtp.cpp -o pam_smtp.so -shared -lpam -lcurl -fPIC
```
## USAGE
```
pam_smtp.so <server[:port]> [starttls|tls] [@domain_name]
```
If ```@domain_name``` is not omitted, ```username``` against the SMTP will be ```PAM_USER@domain_name```.

Example:
```
auth   required   pam_smtp.so   smtp-mail.outlook.com:587  starttls  @live.cn
```
## SECURITY CONSIDERATIONS
**IMPORTANT:** This module disables verification of the SMTP server's TLS certificate (`CURLOPT_SSL_VERIFYPEER` and `CURLOPT_SSL_VERIFYHOST` are both set to 0). This means the connection is vulnerable to man-in-the-middle attacks, and the server's identity is not verified.

This behavior is intentional to maximize ease of use in test or development environments where a trusted certificate may not be available. **You should NOT use this module in production without further modification.**

Before deploying in a production environment, it is strongly recommended that you:
- Set `CURLOPT_SSL_VERIFYPEER` to `1L` and `CURLOPT_SSL_VERIFYHOST` to `2L`.
- Provide a trusted CA certificate bundle using `CURLOPT_CAINFO`.
- Consider enforcing the use of `starttls` or `tls` to guarantee encryption.

This module is provided as open source under the GPLv3 license with no warranty. Users are expected to review and adapt the code to meet their own security requirements.
## LICENSE
pam_smtp is licensed under the [GPLv3](LICENSE) license.
