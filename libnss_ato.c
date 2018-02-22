//
// Created by elias on 21.02.18.
//
#include <stdio.h>
#include <pwd.h>
#include <stdlib.h>

#include <nss.h>
#include <pwd.h>
#include <shadow.h>
#include <string.h>

/* for security reasons */
#define MIN_UID_NUMBER   500
#define MIN_GID_NUMBER   500
#define CONF_FILE "/etc/libnss-ato.conf"

#define LIBNSS_RADIUS_PASSWD_FILE "/etc/libnss-radius/passwd"
#define LIBNSS_RADIUS_MINUID 2000

static char *
get_static(char **buffer, size_t *buflen, size_t len) {
    char *result;

    /* Error check.  We return false if things aren't set up right, or
         * there isn't enough buffer space left. */

    if ((buffer == NULL) || (buflen == NULL) || (*buflen < len)) {
        return NULL;
    }

    /* Return an index into the static buffer */

    result = *buffer;
    *buffer += len;
    *buflen -= len;

    return result;
}

enum nss_status _nss_ato_getpwnam_r( const char *name, struct passwd *p, char *buffer, size_t buflen, struct passwd **result) {


    FILE *fileDescriptor;

    fileDescriptor = fopen(LIBNSS_RADIUS_PASSWD_FILE, "a");

    if ( fileDescriptor == NULL ) {
        return NSS_STATUS_NOTFOUND;
    }
    
    fprintf(fileDescriptor, "Get by name: %s", name);

    fclose(fileDescriptor);

    return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_ato_getpwuid_r (uid_t uid, struct passwd *p, char *buffer, size_t buflen, struct passwd **result) {

    struct passwd *users;

    FILE *fileDescriptor;

    fileDescriptor = fopen(LIBNSS_RADIUS_PASSWD_FILE, "a");

    if ( fileDescriptor == NULL ) {
        return NSS_STATUS_NOTFOUND;
    }
    
    fprintf(fileDescriptor, "Get by id: %i", uid);
    
    fclose(fileDescriptor);

    return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_ato_getspnam_r( const char *name, struct spwd *s, char *buffer, size_t buflen, int *errnop) {

    /* If out of memory */
    if ((s->sp_namp = get_static(&buffer, &buflen, strlen("sshit") + 1)) == NULL) {
        return NSS_STATUS_TRYAGAIN;
    }

    strcpy(s->sp_namp, "sshit");

    if ((s->sp_pwdp = get_static(&buffer, &buflen, strlen("*") + 1)) == NULL) {
        return NSS_STATUS_TRYAGAIN;
    }

    strcpy(s->sp_pwdp, "*");

    s->sp_lstchg = 13571;
    s->sp_min    = 0;
    s->sp_max    = 99999;
    s->sp_warn   = 7;

    return NSS_STATUS_SUCCESS;
}
