#include <stdio.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <resolv.h>	
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include "openssl/ssl.h"
#include "openssl/err.h"

#define ERROR_INT -1
#define BUFFER_SIZE 1024
#define CERT_FILENAME_STR "cert.pem"

int open_listener(int port)			
{   
    int socket_client;
    struct sockaddr_in addr;
 
    socket_client = socket(PF_INET, SOCK_STREAM, 0);

    /* Free output the garbage space in memory */
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    /* Assign the address to the socket */
    if ( bind(socket_client, (struct sockaddr*)&addr, sizeof(addr)) != 0 ) {
        abort();
    }
    /* Maximum 10 clients in the queue */
    if ( listen(socket_client, 10) != 0 ) {
        abort();
    }
    return socket_client;
}

/* Set up ssl context structure */
SSL_CTX* init_ctx() 
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;							
 
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    method = TLSv1_2_server_method();
    ctx = SSL_CTX_new(method);
    if ( ctx == NULL ) {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}
 
/* Loads certificates into an SSL_CTX str */
void load_certs(SSL_CTX* ctx, char* cert_file, char* key_file)
{
    /* Set the local certificate */
    if ( SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* Set the private key */
    if ( SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }

    /* Verify private key */
    if ( !SSL_CTX_check_private_key(ctx) )
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}

/* Serve the connection */
void servlet(SSL* ssl) 
{
    char buf[1024];
    int sd;
    int bytes;

    if ( ERROR_INT == SSL_accept(ssl) ) {
        ERR_print_errors_fp(stderr);
    } else {
        while(1) {
            /* Get request and read the message */
            bytes = SSL_read(ssl, buf, sizeof(buf));

            if ( bytes > 0 ) {	
                buf[bytes] = 0;
                printf(buf);
            } else {
                ERR_print_errors_fp(stderr);
            }
        }
    }
     /* Get socket connection */
    sd = SSL_get_fd(ssl);
    /* Free resources */
    SSL_free(ssl);
    close(sd);
}

int main(int argc, char *argv[])
{
    int port = 8888;
    int server;
    int client;
    struct sockaddr_in addr;
    SSL_CTX *ctx;
    socklen_t len;
    SSL *ssl;
    SSL_library_init();
    ctx = init_ctx();
    load_certs(ctx, CERT_FILENAME_STR, CERT_FILENAME_STR);
    server = open_listener(port);

    len = sizeof(addr);

    /*setting 5 clients at a time to queue*/
    listen(server, 5);
    client = accept(server, (struct sockaddr*)&addr, &len );
    /* Get new SSL state with context */
    ssl = SSL_new(ctx);
    /* Set connection socket to SSL state */
    SSL_set_fd(ssl, client);
    /* Service connection */
    servlet(ssl);
    /* Close server socket */
    close(server);

    /* Free context */
    SSL_CTX_free(ctx);
}