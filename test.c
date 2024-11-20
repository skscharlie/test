#include <getopt.h>
#include <stdio.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <stdlib.h>
#include <resolv.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <errno.h>
#include <sqlite3.h>
#include <openssl/ssl.h>
#include <openssl/dh.h>
#include <openssl/engine.h>
#include <openssl/err.h>

/* Callback function that prints signature name and description
 * @param sig: EVP_SIGNATURE structure containing signature details
 * @param arg: Additional arguments (not used in this function)
 */
void my_callback(EVP_SIGNATURE *sig, void *arg) {
    printf("%s : %s\n", EVP_SIGNATURE_get0_name(sig), EVP_SIGNATURE_get0_description(sig)) ;
}


void handleErrors() {
    ERR_print_errors_fp(stderr) ;
    abort() ;
}

int main(int argc, char* argv[]) {
    /* Create a new DH key exchange structure for party A */
    DH *dh = DH_new() ;
    if(dh == NULL) handleErrors() ;

    if(DH_generate_parameters_ex(dh, 2048, DH_GENERATOR_2, NULL) != 1) handleErrors() ;

    if(DH_generate_key(dh) != 1) handleErrors() ;

    /* Get party A's public key from DH structure */
    const BIGNUM *pub_key_A = DH_get0_pub_key(dh) ;
    /* Get party A's private key from DH structure */
    const BIGNUM *pri_key_A = DH_get0_priv_key(dh) ;
    /* Get the prime modulus p from DH structure */
    const BIGNUM *p = DH_get0_p(dh) ;
    /* Get the generator g from DH structure */
    const BIGNUM *g = DH_get0_g(dh) ;

    DH *dhB = DH_new() ;
    DH_set0_pqg(dhB, p, NULL, g) ;
//    DH_generate_parameters_ex(dhB, 2048, DH_GENERATOR_2, NULL) ;
    DH_generate_key(dhB) ;

    const BIGNUM *pub_key_B = DH_get0_pub_key(dhB) ;
    const BIGNUM *pri_key_B = DH_get0_priv_key(dhB) ;

    printf("%s : %s\n", BN_bn2hex(pri_key_A), BN_bn2hex(pri_key_B)) ;
    printf("\n\n\n===========================================\n") ;
    printf("%s : %s\n", BN_bn2hex(pub_key_A), BN_bn2hex(pub_key_B)) ;
    printf("\n\n\n=========================================\n\n\n") ;

    unsigned char *sharedA = NULL ;
    int sharedA_len = DH_size(dh) ;
    sharedA = OPENSSL_malloc(sharedA_len) ;

    sharedA_len = DH_compute_key(sharedA, pub_key_B, dh) ;

    unsigned char *sharedB = NULL ;
    int sharedB_len = DH_size(dhB) ;
    sharedB = OPENSSL_malloc(sharedB_len) ;

    sharedB_len = DH_compute_key(sharedB, pub_key_A, dhB) ;

    printf("Shared A : ") ;
    for(int i = 0 ; i < sharedA_len ; i++) {
        printf("%02x", sharedA[i]) ;
    }

    printf("\n") ;

    printf("Shared B : ") ;
    for(int i = 0 ; i < sharedB_len ; i++) {
        printf("%02x", sharedB[i]) ;
    }

    printf("\n") ;
    
    OPENSSL_free(sharedA) ;
    OPENSSL_free(sharedB) ;
    DH_free(dh) ;
    DH_free(dhB) ;
}
