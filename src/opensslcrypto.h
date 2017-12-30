/**
 * 
 * \file opensslcrypto.h
 *
 * \brief Low level crypto calls to Openssl library implementation
 *
 */
#if !defined( _S4_OPENSSLCRYPTO_H_ )
#define _S4_OPENSSLCRYPTO_H_


#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>


/**
 * Create a RSA private key and a self signed Certification Authority certificate
 *
 * \param ppcert          pointer to a pointer for the resulting certificate  (set to NULL in case of failure)                                                    
 * \param ppkey           pointer to a pointer for the resulting private key  (set to NULL in case of failure)                             
 * \param pk_fname        zero terminated string containing the path to the file for the private key (PKCS8 PEM format)
 * \param pk_fname_len    size of the primary key filename string
 * \param cert_fname      zero terminated string containing the path to the firle for the CA certificate (X509 PEM format)
 * \param cert_fname_len  size of the CA certificate filename string
 * \param subject         zero terminated string containing the subject of the CA certificate formed as for openssl command line (i.e /CN=X/O=Y/C=Z...)
 * \param subject_len     size of th subject string
 * \param ksize           RSA key size in bits
 * \param password        zero terminated string containing the password, or NULL if no password is to be used
 * \param pass_len        length of the password (ignored if password is set to NULL)
 * \param cdp             zero terminated string containing the URI of the CRL distribution point (ignored if set to NULL)
 * \param cdp_len         size of the CDP string
 *
 * \return 1 in case of success, 0 on failure
 */
int create_self_signed_ca( 
    X509**         ppcert,         
	EVP_PKEY**     ppkey,          
    const char*    pk_fname,       
	const size_t   pk_fname_len,   
    const char*    cert_fname, 
	const size_t   cert_fname_len, 
    const char*    subject,    
	const size_t   subj_len, 
    const unsigned ksize,
    const char*    password,    
	const size_t   pass_len, 
	const char*    cdp,        
	const size_t   cdp_len
);

/**
 * Create a RSA private key 
 *
 * \param nb_bits    size in bits of the RSA key
 * \param filepath   zero terminated string containing the path to key file (PKCS8 PEM)
 * \param path_len   size of the file path string  
 * \param passphrase zero terminated string containing the password, or NULL if no password is to be used 
 * \param path_len   length of the password (ignored if password is set to NULL)                          
 *
 * \return pointer to the private key structure (freeing it is up to the caller), NULL on failure
 *
 */ 
EVP_PKEY* create_rsa_private_key( 
    unsigned nb_bits, 
    const char* filepath,   size_t path_len, 
    const char* passphrase, size_t pass_len 
);


#endif