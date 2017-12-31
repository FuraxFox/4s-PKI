/**
 * 
 * \file  opensslcrypto.c
 *
 * \brief Low level crypto calls to Openssl library implementation
 *
 * License: see LICENSE.md file
 *
 */

//TODO: integrate error management functions from utils.h

#include "opensslcrypto.h"


#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <assert.h>



//////////////////////////////////////////////////////////////// IMPLEMENTATION

static const size_t max_subject_parts = 1024;

struct SRSAPrivateKeyCreationContext 
{
    BIGNUM*   bn; 
    RSA*      rsa; 
    EVP_PKEY* pkey; 
    FILE*     pem_fh;
};

struct SCertSubject 
{
    char **  names;
    size_t*  names_len; 
    char **  vals; 
    size_t*  vals_len;
    unsigned nb_parts;
};


///////////////////////////////////////////////////////////////////////////////
//
static void* _createRSAPrivateKeyCleaner( struct SRSAPrivateKeyCreationContext* ctx, void* ret )
{
    if( NULL!=ctx->bn ) { 
        BN_free(ctx->bn);      
        ctx->bn=NULL;    
    }        
    if( NULL!=ctx->pem_fh ) { 
        fclose( ctx->pem_fh ); 
        ctx->pem_fh=NULL;
    }        
    if( NULL == ret ) {                                         
        if( NULL != ctx->rsa  ) { 
            RSA_free( ctx->rsa );  
            ctx->rsa=NULL; 
        }        
        if( NULL != ctx->pkey ) { 
            EVP_PKEY_free( ctx->pkey ); 
            ctx->pkey=NULL; 
        }
    }
    return ret;
}//eo  _createRSAPrivateKeyCleaner

#define NEWPK_FINISH(ctx,ret,msg) \
    if(1) { \
        fprintf(stderr,"%s createRSAPrivateKey: %s\n", (NULL==ret?"!!":" -"), (msg)); \
        return _createRSAPrivateKeyCleaner((ctx),(ret)); \
    }

EVP_PKEY* create_rsa_private_key( 
    unsigned nb_bits, 
    const char* filepath,   size_t path_len, 
    const char* passphrase, size_t pass_len 
)
{
    assert( nb_bits>32 );
    assert( NULL!=filepath );
    assert( path_len>0 );

    long res = 0;

    struct SRSAPrivateKeyCreationContext ctx; 
    memset( &ctx, 0, sizeof(ctx));

    //////// Initialisation
    ctx.rsa = RSA_new();
    if( NULL == ctx.rsa ) return NULL;

    ctx.bn  = BN_new();
    if( NULL == ctx.bn ) NEWPK_FINISH(&ctx, NULL, "failed to allocate bignumber for RSA key");

    ctx.pem_fh = fopen( filepath, "w" );
    if( NULL == ctx.pem_fh ) NEWPK_FINISH(&ctx, NULL, "failed to open file to store RSA key in");
    
    res = BN_set_word(ctx.bn, RSA_F4);
    if( 1 != res ) NEWPK_FINISH(&ctx, NULL, "failed to set RSA parameters");

    //////// Key creation
    // Generate key (no callback)
    res = RSA_generate_key_ex(ctx.rsa, nb_bits, ctx.bn, NULL); 
    if( 1 != res ) NEWPK_FINISH(&ctx, NULL, "failed to generate RSA key");

    // Convert RSA to PKEY
    ctx.pkey = EVP_PKEY_new(); 
    if( NULL == ctx.pkey ) NEWPK_FINISH(&ctx, NULL, "failed to create private key object");

    res = EVP_PKEY_set1_RSA( ctx.pkey, ctx.rsa );
    if( 1 != res ) NEWPK_FINISH(&ctx, NULL, "failed to copy RSA infos to private key object");

    RSA_free(ctx.rsa); ctx.rsa=NULL; // Valgrind says RSA object is not properly 
                                     // deleted by EVP destruction

    //////// Serialisation
    res = PEM_write_PKCS8PrivateKey( 
        ctx.pem_fh, ctx.pkey, 
        EVP_aes_256_cbc(), 
        (char*)passphrase, pass_len,
        NULL, NULL
    );
    if( 1 != res ) NEWPK_FINISH(&ctx, NULL, "failed to save private key to PEM file");
    
    /////// Cleanup
    NEWPK_FINISH(&ctx, ctx.pkey, "done.");
    
}//eo createPrivKey

#undef NEWPK_FINISH

static int _appendCertExt( X509* cert, int nid, const char * val )
{
    assert( NULL!=cert );

    X509_EXTENSION *ex = NULL;
    X509V3_CTX v3ctx; 

    X509V3_set_ctx(&v3ctx, cert, cert, 0, 0, 0);

    ex = X509V3_EXT_conf_nid( NULL,  &v3ctx, nid, (char*)val );
    if( NULL == ex ) { 
        fprintf( stderr, "!! _appendCertExt: failed to create extension\n"); 
        return 0; 
    }

    if( X509_add_ext(cert,ex,-1) != 1 ) { 
        fprintf( stderr, "!! _appendCertExt: failed to append extension\n"); 
        return 0; 
    }

    X509_EXTENSION_free(ex);

    return 1;
}//eo _appendCertExt

// variadic macros and strings pasting are so painful, you dont want to touch that
#define NEXTCERT_FAILED(fmt,...) \
    if(1) { \
        fprintf( stderr, "!! createCACert: " fmt "\n" , ## __VA_ARGS__ ); \
        X509_free(cert); \
        return NULL;     \
    } 

#define ADD_EXT(id,val) \
    if( _appendCertExt(cert,(id),(val)) != 1 ) \
        NEXTCERT_FAILED("failed to add attribute %s",val); 

static X509* _createCACert( 
        EVP_PKEY*      pkey, 
        const char*    filename, 
		const struct SCertSubject * subject,
        const unsigned duration_days,
        const char *   crl_dist_point,
		const size_t   cdp_len __attribute__((unused))
)
{
    assert( NULL!=pkey          );
    assert( NULL!=filename      );
    assert( NULL!=subject       );
    assert( NULL!=subject->names[0] );
    assert( NULL!=subject->vals[0] );
    assert( subject->nb_parts>0  );
    assert( duration_days > 0   );

    FILE *          fh = NULL;
    X509 *        cert = NULL;
    X509_NAME *   name = NULL;

    long res=0;

    cert = X509_new(); 
    if( NULL == cert ) return NULL;
    
    res = X509_set_version(cert, 2); 
    if( 1 != res ) NEXTCERT_FAILED("failed to set certificate version");

    res = ASN1_INTEGER_set( X509_get_serialNumber(cert), 1); 
    if( 1!=res ) NEXTCERT_FAILED("failed to set serial number"); 

    long duration_secs = duration_days*24*3600;

    res = (long) X509_gmtime_adj( X509_get_notBefore(cert), 0);
    if( 0 == res ) NEXTCERT_FAILED("failed to set start of cryptoperiod");

    res = (long)X509_gmtime_adj( X509_get_notAfter(cert), duration_secs );
    if( 0 == res ) NEXTCERT_FAILED("failed to set end of cryptoperiod");

    res = X509_set_pubkey( cert, pkey);
    if( 1 != res ) NEXTCERT_FAILED("failed to set public key to certificate"); 
    
    name = X509_get_subject_name(cert); 
    if( NULL == name ) NEXTCERT_FAILED("failed to get certificate name object");

    for( unsigned i=0; i < subject->nb_parts; i++ ) {
        res = X509_NAME_add_entry_by_txt(
            name, subject->names[i], MBSTRING_ASC, (unsigned char*)subject->vals[i], -1, -1, 0
        ); 
        if ( 1 != res ) {
            NEXTCERT_FAILED("failed to add subject part: %s=%s", subject->names[i], subject->vals[i] );
        }
    }

    res = X509_set_issuer_name(cert, name);
    if( 1 != res  ) NEXTCERT_FAILED("failed to set issuer name");

    ADD_EXT( NID_key_usage,               "critical,keyCertSign,cRLSign");
    ADD_EXT( NID_basic_constraints,       "critical,CA:TRUE"            );
    ADD_EXT( NID_subject_key_identifier,  "hash"                        );
    ADD_EXT( NID_authority_key_identifier,"keyid:always,issuer:always"  );
    if( NULL != crl_dist_point ) {
        ADD_EXT( NID_crl_distribution_points, crl_dist_point );
    }
    
    res = X509_sign(cert, pkey, EVP_sha256());

    if( 0 ==res ) NEXTCERT_FAILED("certificate signature failed");
    
    fh = fopen(filename, "wb"); 
    if( NULL==fh ) NEXTCERT_FAILED("failed to open file");

    res = PEM_write_X509( fh, cert);
    if( 1 != res ) NEXTCERT_FAILED("write certificate file");

    fclose(fh);

    return cert;
}//eo createCACert
#undef NEXTCERT_FAILED 
#undef ADD_EXT



/*
 * Extract a string and create a new copy
 */ 
static char * _mkString( const char* src, size_t start, size_t end, size_t* len ) 
{
	size_t sze = (end-start)+1;
    char * val = calloc(1, sze );
    *len = 0;
    if( NULL==val ) {
		fprintf(stderr, "!!!! mkstring: failed calloc of %ld [%ld .. %ld ]\n", sze, start, end );
        return NULL;
    }
    memcpy( val, src+start, sze-1 );
    val[sze-1] ='\0';
	*len = sze-1;
	return val;
}//eo _mkString

/*
 * Transform a Subject string formed as /name1=val1/name2=val2/name3=val3
 * returns nb parts if parsing succedeed / 0 if it failed
 *
 */ 
static unsigned  _splitSubject( const char * subj_str, const size_t subj_len, struct SCertSubject* subj ) 
{
    assert( NULL != subj );

    subj->names     = NULL;
    subj->names_len = NULL;
    subj->vals      = NULL;
    subj->vals_len  = NULL;

    char*  vars[max_subject_parts];
    char*  vals[max_subject_parts];
    size_t vars_len[max_subject_parts];
    size_t vals_len[max_subject_parts];

    ///// Parsing source string
    unsigned count = 0;
    size_t       i = 0;
    size_t       var_start=0;
    size_t       val_start=0;
    char         c='\0';
    while( (i<subj_len) && (c = subj_str[i]) ) {
        if( c == '/' ) {
            var_start=i+1;
            if( 1 != var_start ) {
				if( 0 == val_start ) {
					fprintf( stderr, "!! invalid subject: cant find its start\n");
					return 0;
				}
                // non first part: copying (val_start,i-1)
                // increase count
                size_t len = 0;
                vals[count] = _mkString( subj_str, val_start, i, &len );
				if( 0 == len ) {
					fprintf(stderr,"!!! failed to allocate val\n");
					return 0;
				}
                vals_len[count] = len;
                count++;
				if( max_subject_parts == count ) {
					fprintf(stderr,"!!! to many parts to the subject\n");
					return 0;
				}
            }
        } else if( c =='=' ) {
			if( 0 == var_start ) {
				// = before / = invalid string
				fprintf(stderr, "!!! invalid subject: value without name\n");
				return 0;
			}
            // start of value
            val_start=i+1;
            // copy (var_start,i-1)
            size_t len = 0;
            vars[count] = _mkString( subj_str, var_start, i, &len );
			if( 0 == len ) {
				fprintf(stderr,"!!! failed to allocate var\n");
				return 0;
			}
            vars_len[count] = len;
        }
        i++;
    }
	// fin de chaine copie de la derniere valeur
	if( (0 == var_start) || (0== val_start) ) {
		fprintf(stderr,"!!! malformed subject: no delimiter\n");
		return 0;
	}
	size_t len = 0;
    vals[count] = _mkString( subj_str, val_start, i, &len );
	if( 0 == len ) {
		fprintf(stderr,"!!! failed to allocate val\n");
		return 0;
	}
    vals_len[count] = len;
    count++;


	///// Copying results (leaking some memory on failure, but if calloc fails all is lost anyway)

	subj->nb_parts = count;

	subj->names = calloc( count, sizeof(char*)  );
	if( NULL == subj->names ) return 0;
	memcpy( subj->names, vars, count*sizeof(char*)  );

	subj->names_len = calloc( count, sizeof(size_t) );
	if( NULL == subj->names_len ) return 0;
	memcpy( subj->names_len, vars_len,  count*sizeof(size_t) );

	subj->vals = calloc( count, sizeof(char*)  );
	if( NULL == subj->vals ) return 0;
	memcpy( subj->vals, vals, count*sizeof(char*) );
	
	subj->vals_len  = calloc( count, sizeof(size_t) );
	if( NULL == subj->vals_len ) return 0;
	memcpy( subj->vals_len,  vals_len, count*sizeof(size_t) );


    return count;
}//eo _splitSubject;

/**
 * Free the subject memory 
 */ 
static void _clearSubject( struct SCertSubject* subj ) 
{
    assert( NULL != subj );    
    if( subj->nb_parts > 0 ) {
        assert( NULL != subj->names );
        assert( NULL != subj->vals );
    }

    for( unsigned i=0; i<subj->nb_parts; i++ ) {
        if( NULL != subj->names[i] ) { free( subj->names[i] ); }
        if( NULL != subj->vals[i]  ) { free( subj->vals[i] );  }
    }
    if( NULL!=subj->vals  ) free(subj->vals);
    if( NULL!=subj->names ) free(subj->names);
	if( NULL!=subj->vals_len  ) free(subj->vals_len);
    if( NULL!=subj->names_len ) free(subj->names_len);

    memset( subj, 0, sizeof(struct SCertSubject) );
}//eo _clearSubject

static void _printSubject( FILE* fh, const struct SCertSubject* subj ) 
{
	fprintf( fh, "Subject: %p\n", subj );
    for( unsigned i=0; i < subj->nb_parts; i++ ) {
        fprintf( fh, "\t- var[%s] = val[%s]\n", subj->names[i], subj->vals[i] );
    }
}//eo _printSubject


int create_self_signed_ca( 
    X509**     pcert,       EVP_PKEY** ppkey,
    const char* pk_fname,   const size_t pk_fname_len, 
    const char* cert_fname, const size_t cert_fname_len, 
    const char* subject,    const size_t subj_len, 
    const unsigned ksize,
    const char* password,   const size_t pass_len, 
	const char* cdp,        const size_t cdp_len
)
{
    assert(NULL!=pcert);
    assert(NULL!=ppkey);
    assert(NULL!=pk_fname);
    assert(pk_fname_len>0);
    assert(NULL!=cert_fname);
    assert(cert_fname_len>0);
    assert(NULL!=subject);
    assert(subj_len>0);
    assert(NULL!=password);
    assert(pass_len>0);

	*ppkey = NULL;
	*pcert=NULL;

	// subject parsing
    struct SCertSubject subj_obj;
    int nb_parts = _splitSubject( subject, subj_len, &subj_obj);
	if( 0 == nb_parts ) { 
		fprintf( stderr, "!! createSelfSignedCA: subject parsing failed\n" );
		return 0;	
	} 

	// private key creation
	EVP_PKEY* pkey = create_rsa_private_key( ksize, pk_fname, pk_fname_len, password, pass_len );
	if( NULL == pkey ) { 
		fprintf( stderr, "!! createSelfSignedCA: private key creation failed\n" );
		return 0; 
	} 
	
	// certificate creation
	X509* cert = _createCACert( pkey, cert_fname, &subj_obj, 365, cdp, cdp_len );
    if( NULL == cert ) {
		fprintf( stderr, "!! createSelfSignedCA: certificate creation failed\n" );
		EVP_PKEY_free(pkey); 
		return 0;
	}

	_clearSubject( &subj_obj );

	*pcert = cert;
	*ppkey = pkey;

	return 1;
}
//eo createSelfSignedCA

