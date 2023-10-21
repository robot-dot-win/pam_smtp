## DESCRIPTION
pam_smtp is a Linux PAM module which provides a way to authenticate users against an SMTP server.

On success it returns PAM_SUCCESS, otherwise it returns PAM_AUTH_ERR, PAM_SERVICE_ERR, PAM_BUF_ERR or PAM_PERM_DENIED.

No credentials are awarded by this module.
## BUILD
The source program is a single C++11 file.

Dependent packages: pam-devel, libcurl-devel

```bash
$ g++ pam_smtp.cpp -o pam_smtp.so -shared -lpam -lcurl -fPIC
```
## USAGE
```
pam_smtp.so <server[:port]> [starttls|tls]
```
Example:
```
auth    required    pam_smtp.so     smtp-mail.outlook.com:587 starttls
```
## LICENSE

pam_smtp is licensed under the [GPLv3](LICENSE) license.