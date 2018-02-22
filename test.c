
#include<stdio.h>
#include<pwd.h>

struct passwd *getpwnam(const char *name);

int main(int argsLen, char **args){

	if(argsLen < 2){
		puts("You must provide user names as program arguments!!!");
		return -1;
	}

	for(size_t i = 1; i < argsLen; i++){
		struct passwd *user = getpwnam(args[i]);

		if( user == NULL ){
			printf("No user by name %s\n", args[i]);
			continue;
		}

		printf("%s UID=%i\n", args[i], user->pw_uid);
		
	}

	
	return 0;
}
