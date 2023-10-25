//  pam_smtp module, v1.0.1, 2023-10-21
//
//  Copyright (C) 2023, Martin Young <martin_young@live.cn>
//
//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or any
//  later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with this program. If not, see <https://www.gnu.org/licenses/>.
//------------------------------------------------------------------------

#include <string>
#include <cstring>
#include <syslog.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <curl/curl.h>

using namespace std;

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    int retval;
    const char *proto[] = {"smtp", "smtps"};
    const char *puser, *ppwd, *pproto;
    long usessl;
    CURLcode clcode;

    struct Tcurl {
        CURL *hd;
        Tcurl(): hd(nullptr) {}
        Tcurl(CURL *p) { hd=p; }
        ~Tcurl() { if(hd) curl_easy_cleanup(hd); }
    };

    switch(argc) {
    case 0:
        pam_syslog(pamh, LOG_ERR, "No option");
        return PAM_SERVICE_ERR;
    case 1:
        pproto = proto[0];
        usessl = CURLUSESSL_NONE;
        break;
    default:
        usessl = CURLUSESSL_CONTROL;
        if( strcmp(argv[1], "starttls")==0 )
            pproto = proto[0];
        else if( strcmp(argv[1], "tls")==0 )
            pproto = proto[1];
        else {
            pam_syslog(pamh, LOG_ERR, "Bad option: \"%s\"", argv[1]);
            return PAM_SERVICE_ERR;
        }
    }

    if( (retval=pam_get_item(pamh, PAM_USER, (const void **)&puser)) != PAM_SUCCESS ) {
        pam_syslog(pamh, LOG_ERR, "Cannot determine username: %s", pam_strerror(pamh, retval));
        return retval;
    }
    if( !(puser && *puser) ) {
        pam_syslog(pamh, LOG_ERR, "Cannot determine username");
        return PAM_SERVICE_ERR;
    }

    if( (retval=pam_get_authtok(pamh, PAM_AUTHTOK, &ppwd, NULL)) != PAM_SUCCESS ) {
        pam_syslog(pamh, LOG_ERR, "Cannot determine password: %s", pam_strerror(pamh, retval));
        return retval;
    }
    if( !(ppwd && *ppwd) ) {
        pam_syslog(pamh, LOG_ERR, "Cannot determine password");
        return PAM_SERVICE_ERR;
    }

    Tcurl curl(curl_easy_init());
    if( !curl.hd ) {
        pam_syslog(pamh, LOG_ERR, "CURL library initialization failure: curl_easy_init()");
        return PAM_SERVICE_ERR;
    }

    do {
        if( (clcode=curl_easy_setopt(curl.hd, CURLOPT_URL, (string(pproto)+"://"+string(argv[0])).c_str())) != CURLE_OK ) break;
        if( (clcode=curl_easy_setopt(curl.hd, CURLOPT_USERPWD, (string(puser)+":"+string(ppwd)).c_str())) != CURLE_OK ) break;
        if( (clcode=curl_easy_setopt(curl.hd, CURLOPT_SSL_VERIFYPEER, 0L)) != CURLE_OK ) break;
        if( (clcode=curl_easy_setopt(curl.hd, CURLOPT_SSL_VERIFYHOST, 0L)) != CURLE_OK ) break;
        if( (clcode=curl_easy_setopt(curl.hd, CURLOPT_USE_SSL, usessl)) != CURLE_OK ) break;
    } while(false);
    if( clcode != CURLE_OK ) {
        pam_syslog(pamh, LOG_ERR, "CURL library function call failure: curl_easy_setopt()");
        return PAM_SERVICE_ERR;
    }

    if( (clcode=curl_easy_perform(curl.hd)) != CURLE_OK ) {
        pam_syslog(pamh, LOG_NOTICE, "Access denied: %s", curl_easy_strerror(clcode));
        return PAM_AUTH_ERR;
    }

    return PAM_SUCCESS;
}

int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return PAM_SUCCESS;
}

int pam_sm_acct_mgmt (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return pam_sm_authenticate(pamh, flags, argc, argv);
}

int pam_sm_open_session (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return pam_sm_authenticate(pamh, flags, argc, argv);
}

int pam_sm_close_session (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return pam_sm_authenticate(pamh, flags, argc, argv);
}

int pam_sm_chauthtok (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return pam_sm_authenticate(pamh, flags, argc, argv);
}
