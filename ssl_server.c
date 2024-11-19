#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define FAIL        -1

int OpenListner(int port) {
    int sd ;
    struct sockaddr_in addr ;

    sd = socket(AF_INET, SOCK_STREAM, 0) ;
    bzero(&addr, sizeof(addr)) ;

    addr.sin_family = AF_INET ;
    addr.sin_port = htons(port) ;
    addr.sin_addr.s_addr = INADDR_ANY ;

    if(bind(sd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("can't bind port") ;
        abort() ;
    }

    if(listen(sd, 10) != 0) {
        perror("Can't configure listening port") ;
        abort() ;
    }

    return sd ;
}

static int verify_callback(int preverify_ok, X509_STORE_CTX *ctx) {
    printf("in verify callback : %d\n", preverify_ok) ;
    if(preverify_ok == 0) {
        int err = X509_STORE_CTX_get_error(ctx) ;
        int err_depth = X509_STORE_CTX_get_error_depth(ctx) ;
        const char *err_msg = X509_verify_cert_error_string(err) ;

        fprintf(stderr, "[%d] : %s\n", err, err_msg) ;
        fprintf(stderr, "depth : %d\n", err_depth) ;
    }
    return 1 ;
}

SSL_CTX *InitServerCTX(void) {
    const SSL_METHOD *method ;
    SSL_CTX *ctx ;

    OpenSSL_add_all_algorithms() ;
    SSL_load_error_strings() ;

    method = TLS_server_method() ;

    ctx = SSL_CTX_new(method) ;
    if(ctx == NULL) {
        ERR_print_errors_fp(stderr) ;
        abort() ;
    }
    
    if(SSL_CTX_load_verify_locations(ctx, "certs/nestfield_cert.pem", NULL) != 1) {
        fprintf(stderr, "루트 CA 인증서 load fail\n") ;
        abort() ;
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_callback);

    return ctx ;
}

void LoadCertificates(SSL_CTX *ctx, char *CertFile, char *KeyFile) {
    if(SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr) ;
        abort() ;
    }

    printf("read cert file ok\n") ;

    if(SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr) ;
        abort() ;
    }

    printf("read key file ok\n") ;

    if(!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the public certificate\n") ;
        abort() ;
    }
}

void ShowCerts(SSL *ssl) {
    X509 *cert ;
    char *line ;

    cert = SSL_get_peer_certificate(ssl) ;

    if(cert != NULL) {
        printf("Server certificates: \n") ;
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0) ;
        printf("Subject : %s\n", line) ;
        free(line) ;

        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0) ;
        printf("Issuer: %s\n", line) ;
        free(line) ;
        X509_free(cert) ;
    }
    else {
        printf("Info: No client certificates configured. \n") ;
    }
}


void Servlet(SSL *ssl) {
    char buf[1024] = {0} ;
    int sd, bytes ;
    const char *serverResponse = "Hi, hello" ;

    if(SSL_accept(ssl) == FAIL) {
        ERR_print_errors_fp(stderr) ;
    }
    else {
        ShowCerts(ssl) ;
        bytes = SSL_read(ssl, buf, sizeof(buf)) ;
        buf[bytes] = 0 ;

        printf("client message : %s\n", buf) ;
        SSL_write(ssl, serverResponse, strlen(serverResponse)) ;
    }

    sd = SSL_get_fd(ssl) ;
    SSL_free(ssl) ;
    close(sd) ;
}

int main(int argc, char **argv) {
    SSL_CTX *ctx ;
    int server ;
    char *portnum ;

    SSL_library_init() ;
    portnum = argv[1] ;
    ctx = InitServerCTX() ;
    LoadCertificates(ctx, "certs/secc_cert.pem", "certs/secc_key.pem") ;

    server = OpenListner(atoi(portnum)) ;

    while(1) {
        struct sockaddr_in addr ;
        socklen_t len = sizeof(addr) ;
        SSL *ssl ;

        int client = accept(server, (struct sockaddr *)&addr, &len) ;
        printf("connection : %s: %d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port)) ;

        ssl = SSL_new(ctx) ;
        SSL_set_fd(ssl, client) ;
        Servlet(ssl) ;
    }

    close(server) ;
    SSL_CTX_free(ctx) ;
}