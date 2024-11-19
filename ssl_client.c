#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define FAIL -1

int OpenConnection(const char *hostname, int port) {
    int sd ;
    struct hostent *host ;
    struct sockaddr_in addr ;

    if((host = gethostbyname(hostname)) == NULL) {
        perror(hostname) ;
        abort() ;
    }

    sd = socket(AF_INET, SOCK_STREAM, 0) ;
    bzero(&addr, sizeof(addr)) ;
    addr.sin_family = AF_INET ;
    addr.sin_port = htons(port) ;
    addr.sin_addr.s_addr = *(long*)(host->h_addr) ;

    if(connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        close(sd) ;
        perror(hostname) ;
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

SSL_CTX *InitCtx(void) {
    const SSL_METHOD *method ;
    SSL_CTX *ctx ;

    OpenSSL_add_all_algorithms() ;
    SSL_load_error_strings() ;

    method = TLS_client_method() ;
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
        int ret ;
        if((ret = SSL_get_verify_result(ssl)) == X509_V_OK)
            printf("서버 인증서 검증 성공\n") ;
        else {
            printf("서버 인증 실패: %d\n", ret) ;
            ERR_print_errors_fp(stderr) ;
        }

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

int main(int argc, char **argv) {
    SSL_CTX *ctx ;
    int server ;
    SSL *ssl ;
    char buf[1024] ;
    char *hostname, *portnum ;
    char *clientRequest = "Hello, server?" ;

    SSL_library_init() ;
    hostname = argv[1] ;
    portnum = argv[2] ;

    ctx = InitCtx() ;
    LoadCertificates(ctx, "certs/evcc_cert.pem", "certs/evcc_key.pem") ;

    server = OpenConnection(hostname, atoi(portnum)) ;
    ssl = SSL_new(ctx) ;
    SSL_set_fd(ssl, server) ;

    if(SSL_connect(ssl) == FAIL) {
        ERR_print_errors_fp(stderr) ;
    } 
    else {
        printf("\n\nConnected with %s encryption\n", SSL_get_cipher(ssl)) ;
        ShowCerts(ssl) ;

        SSL_write(ssl, clientRequest, strlen(clientRequest)) ;
        
        int num = SSL_read(ssl, buf, sizeof(buf)) ;
        buf[num] = 0 ;
        printf("Received : %s\n", buf) ;
        SSL_free(ssl) ;
    }

    close(server) ;
    SSL_CTX_free(ctx) ;

    return 0 ;
}