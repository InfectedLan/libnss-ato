//
// Created by elias on 21.02.18.
//

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>

#include <nss.h>
#include <pwd.h>

#define TRUE 1
#define FALSE 0

#define NSS_FILE "/etc/libnss-radius.passwd"
#define PAM_FILE "/etc/pam_radius_auth.users"
#define BUFFER_SIZE 256
#define UID_START 2000

static char *get_static(char **buffer, size_t *buflen, size_t len) {
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

static int search_pam_file(const char *name){
	
	FILE *fp = fopen(PAM_FILE, "r");

	if(fp == NULL){
		return 0;
	}
	
	
	while(!feof(fp)){

		char buffer[BUFFER_SIZE];

		if (fgets(buffer, BUFFER_SIZE, fp) == NULL){
			return FALSE;
		}
		
		size_t i = 0;
		while (i < BUFFER_SIZE - 1 && buffer[i] != 10) {
			i++;
		}
		buffer[i] = 0;
		
		if (strcmp(buffer, "") == 0) {
			continue;
		}

		if (strcmp(buffer, name) == 0) {
			fclose(fp);
			return TRUE;
		}
	}	
	
	fclose(fp);
	return FALSE;
}

static int search_nss_file(const char *name, struct passwd *result, int *nextUID){

	FILE *fp = fopen(NSS_FILE, "r");

	if(fp == NULL){
		return FALSE;
	}

	struct passwd *user;
	int foundMatch = FALSE;

	*nextUID = UID_START;

	while(user = fgetpwent(fp), user != NULL){

		if(strcmp(name, user->pw_name) == 0){
		
			*result = *user;

			result->pw_name = malloc(strlen(user->pw_name) + 1);
			strcpy(result->pw_name, user->pw_name);

			result->pw_passwd = malloc(strlen(user->pw_passwd) + 1);
			strcpy(result->pw_passwd, user->pw_passwd);

			result->pw_gecos = malloc(strlen(user->pw_gecos) + 1);
			strcpy(result->pw_gecos, user->pw_gecos);

			result->pw_dir = malloc(strlen(user->pw_dir) + 1);
			strcpy(result->pw_dir, user->pw_dir);

			result->pw_shell = malloc(strlen(user->pw_shell) + 1);
			strcpy(result->pw_shell, user->pw_shell);

			foundMatch = TRUE;
		}

		*nextUID = user->pw_uid + 1;
	}

	fclose(fp);
	return foundMatch;
}

static int moveMemory(char **ptr, char **buffer, size_t *buflen){

	char *charbuf = get_static(buffer, buflen, strlen(*ptr) + 1);

	if (charbuf == NULL){
		return FALSE;
	}

	strcpy(charbuf, *ptr);

	*ptr = charbuf;
	return TRUE;
}

enum nss_status _nss_radius_getpwnam_r(const char *name, struct passwd *result_buf, char *buffer, size_t buflen, struct passwd **result) {

	*result = NULL;

	int nextUID;

	if (search_nss_file(name, result_buf, &nextUID)){

		syslog(LOG_AUTH, "Found user %s with UID:%i in nss file.\n", result_buf->pw_name, result_buf->pw_uid);
		
		if (!moveMemory(&result_buf->pw_name, &buffer, &buflen )  ||
		    !moveMemory(&result_buf->pw_passwd, &buffer, &buflen )||
		    !moveMemory(&result_buf->pw_gecos, &buffer, &buflen ) ||
	 	    !moveMemory(&result_buf->pw_dir, &buffer, &buflen )   ||
		    !moveMemory(&result_buf->pw_shell, &buffer, &buflen )){

			return NSS_STATUS_TRYAGAIN;
		}

		*result = result_buf;
		return NSS_STATUS_SUCCESS;
	}

	if (search_pam_file(name)){

		FILE *fp = fopen(NSS_FILE, "a");

		if(fp == NULL){
			syslog(LOG_AUTH, "Failed to open nss file\n");
			return NSS_STATUS_NOTFOUND;
		}
		
		fprintf(fp, "%s:x:%i:%i:,,,:/tmp:/bin/bash\n", name, nextUID, nextUID);

		fclose(fp);

		result_buf->pw_name = malloc(strlen(name) + 1);
		strcpy(result_buf->pw_name, name);

		result_buf->pw_uid = nextUID;
		result_buf->pw_gid = nextUID;
		result_buf->pw_passwd = "x";
		result_buf->pw_gecos = "";
		result_buf->pw_dir = "/tmp";
		result_buf->pw_shell = "/bin/bash";

		if (!moveMemory(&result_buf->pw_name, &buffer, &buflen )  ||
		    !moveMemory(&result_buf->pw_passwd, &buffer, &buflen )||
		    !moveMemory(&result_buf->pw_gecos, &buffer, &buflen ) ||
	 	    !moveMemory(&result_buf->pw_dir, &buffer, &buflen )   ||
		    !moveMemory(&result_buf->pw_shell, &buffer, &buflen )){
			return NSS_STATUS_TRYAGAIN;
		}
		
		syslog(LOG_AUTH, "Registered user %s\n", name);
		
		*result = result_buf;
		return NSS_STATUS_SUCCESS;
	}

	syslog(LOG_AUTH, "Didnt find user %s in either pam or nss file\n", name);
	return NSS_STATUS_NOTFOUND;
}
