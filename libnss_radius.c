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
#define CONF_FILE "/etc/libnss-radius.conf"

#define LIBNSS_RADIUS_PASSWD_FILE "/etc/libnss-radius/passwd"
#define LIBNSS_RADIUS_MINUID 2000

struct passwd *readRadiusPasswd(FILE *fileDescriptor, size_t *size, size_t *nextUID){

    size_t passwdArrayBufferSize = 64;
    size_t passwdArrayIndex = 0;
    struct passwd* passwdArray = malloc(sizeof(struct passwd) * passwdArrayBufferSize);

    if(passwdArray == NULL)
        return NULL;

    while ( !feof(fileDescriptor) ){

        struct passwd *p = fgetpwent(fileDescriptor);
        if(p == NULL)
            break;

        if(passwdArrayIndex >= passwdArrayBufferSize){

            size_t oldBufferSize = passwdArrayBufferSize;
            passwdArrayBufferSize += 64;

            struct passwd* oldPasswd = passwdArray;
            passwdArray = malloc(sizeof(struct passwd) * passwdArrayBufferSize);

            if(passwdArray == NULL)
                return NULL;

            for(size_t i = 0; i < oldBufferSize; i++){
                passwdArray[i] = oldPasswd[i];
            }

            free(oldPasswd);
        }


        struct passwd* curPasswd = &passwdArray[passwdArrayIndex++];

        *curPasswd = *p;

        curPasswd->pw_name = malloc(sizeof(char) * (strlen(p->pw_name) + 1));
        strcpy(curPasswd->pw_name, p->pw_name);

        curPasswd->pw_gecos = malloc(sizeof(char) * (strlen(p->pw_gecos) + 1));
        strcpy(curPasswd->pw_gecos, p->pw_gecos);

        curPasswd->pw_passwd = malloc(sizeof(char) * (strlen(p->pw_passwd) + 1));
        strcpy(curPasswd->pw_passwd, p->pw_passwd);

        curPasswd->pw_dir = malloc(sizeof(char) * (strlen(p->pw_dir) + 1));
        strcpy(curPasswd->pw_dir, p->pw_dir);

        curPasswd->pw_shell = malloc(sizeof(char) * (strlen(p->pw_shell) + 1));
        strcpy(curPasswd->pw_shell, p->pw_shell);

        if(p->pw_uid >= *nextUID)
            *nextUID = p->pw_uid + 1;
    }

    *size = passwdArrayIndex;

    return passwdArray;
}

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

int move_str(char **dst, const char *src, char *buffer, size_t buflen){

    /* If out of memory */
    if ((*dst = get_static(&buffer, &buflen, (int) strlen(src) + 1)) == NULL) {
        return 0;
    }

    strcpy(*dst, src);

    return 1;
}

enum nss_status _nss_radius_getpwnam_r( const char *name, struct passwd *p, char *buffer, size_t buflen, int *errnop) {

    struct passwd *users;

    FILE *fileDescriptor;

    fileDescriptor = fopen(LIBNSS_RADIUS_PASSWD_FILE, "r");

    if ( fileDescriptor == NULL ) {
        return NSS_STATUS_NOTFOUND;
    }

    size_t usersSize = 0;
    size_t nextUID = 0;

    users = readRadiusPasswd(fileDescriptor, &usersSize, &nextUID);
    if(users == NULL && usersSize != 0)
        return NSS_STATUS_TRYAGAIN;

    if(nextUID == 0)
        nextUID = LIBNSS_RADIUS_MINUID;

    fclose(fileDescriptor);

    for( size_t i = 0; i < usersSize; i++ ){

        if( strcmp(name, users[i].pw_name) == 0 ) {

            p->pw_uid = users[i].pw_uid;
            p->pw_gid = users[i].pw_gid;

            if ( !move_str(&(p->pw_name), users[i].pw_name, buffer, buflen) )
                return NSS_STATUS_TRYAGAIN;
            if ( !move_str(&(p->pw_passwd), users[i].pw_passwd, buffer, buflen) )
                return NSS_STATUS_TRYAGAIN;
            if ( !move_str(&(p->pw_gecos), users[i].pw_gecos, buffer, buflen) )
                return NSS_STATUS_TRYAGAIN;
            if ( !move_str(&(p->pw_dir), users[i].pw_dir, buffer, buflen) )
                return NSS_STATUS_TRYAGAIN;
            if ( !move_str(&(p->pw_shell), users[i].pw_shell, buffer, buflen) )
                return NSS_STATUS_TRYAGAIN;

            return NSS_STATUS_SUCCESS;
        }
    }


    uid_t uid = (uid_t) nextUID;
    gid_t gid = (gid_t) nextUID;
    char *pass = "x";
    char *gecos = "";
    char *dir = "/home/";
    char *shell = "/bin/bash";

    p->pw_uid = uid;
    p->pw_gid = gid;

    if ( !move_str(&(p->pw_name), name, buffer, buflen) )
        return NSS_STATUS_TRYAGAIN;
    if ( !move_str(&(p->pw_passwd), pass, buffer, buflen) )
        return NSS_STATUS_TRYAGAIN;
    if ( !move_str(&(p->pw_gecos), gecos, buffer, buflen) )
        return NSS_STATUS_TRYAGAIN;
    if ( !move_str(&(p->pw_dir), dir, buffer, buflen) )
        return NSS_STATUS_TRYAGAIN;
    if ( !move_str(&(p->pw_shell), shell, buffer, buflen) )
        return NSS_STATUS_TRYAGAIN;

    fileDescriptor = fopen(LIBNSS_RADIUS_PASSWD_FILE, "a");

    fprintf(fileDescriptor, "%s:%s:%i:%i:%s:%s:%s\n", name, pass, uid, gid, gecos, dir, shell);

    fclose(fileDescriptor);

    return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_radius_getpwuid_r( uid_t uid, struct passwd *p, char *buffer, size_t buflen, int *errnop) {

    struct passwd *users;

    FILE *fileDescriptor;

    fileDescriptor = fopen(LIBNSS_RADIUS_PASSWD_FILE, "r");

    if ( fileDescriptor == NULL ) {
        return NSS_STATUS_NOTFOUND;
    }

    size_t usersSize = 0;
    size_t nextUID = 0;

    users = readRadiusPasswd(fileDescriptor, &usersSize, &nextUID);
    if(users == NULL && usersSize != 0)
        return NSS_STATUS_TRYAGAIN;

    fclose(fileDescriptor);

    for( size_t i = 0; i < usersSize; i++ ){

        if( uid == users[i].pw_uid ) {

            p->pw_uid = users[i].pw_uid;
            p->pw_gid = users[i].pw_gid;

            if ( !move_str(&(p->pw_name), users[i].pw_name, buffer, buflen) )
                return NSS_STATUS_TRYAGAIN;
            if ( !move_str(&(p->pw_passwd), users[i].pw_passwd, buffer, buflen) )
                return NSS_STATUS_TRYAGAIN;
            if ( !move_str(&(p->pw_gecos), users[i].pw_gecos, buffer, buflen) )
                return NSS_STATUS_TRYAGAIN;
            if ( !move_str(&(p->pw_dir), users[i].pw_dir, buffer, buflen) )
                return NSS_STATUS_TRYAGAIN;
            if ( !move_str(&(p->pw_shell), users[i].pw_shell, buffer, buflen) )
                return NSS_STATUS_TRYAGAIN;

            return NSS_STATUS_SUCCESS;
        }
    }

    return NSS_STATUS_NOTFOUND;
}

enum nss_status _nss_radius_getspnam_r( const char *name, struct spwd *s, char *buffer, size_t buflen, int *errnop) {

    /* If out of memory */
    if ((s->sp_namp = get_static(&buffer, &buflen, strlen(name) + 1)) == NULL) {
        return NSS_STATUS_TRYAGAIN;
    }

    strcpy(s->sp_namp, name);

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
