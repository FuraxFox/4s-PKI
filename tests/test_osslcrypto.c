#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <time.h>
#include <CUnit/Basic.h> 
#include "opensslcrypto.h"
#include "utils.h"


void OpenSSLCrypto_CACreation_Basic_Test( void )
{
	//TODO use test framework tools
    const char * subjects[] = { 
		"/C=FR/O=Goupilland/CN=RootCA" , 
		"/DC=net/DC=goupilland/DC=ca", 
		"/CN=Root CA/OU=Security/O=Goupilland organisation" 
	};

	const char* CDP = "URI:http://www.goupilland.net/goupilland.crl";

    const char* pkfilepattern = "ca-key-%02u.pem";
    const char* password   = "Password1";
    char pkfilename[1024];
    unsigned  ksize = 1024;
    
    const char *cafilepattern = "ca-cert-%02u.pem";
    char cafilename[1024];

    X509*      cert = NULL;
    EVP_PKEY*  pkey = NULL;
    for( int i=0; i<3; i++ ) {
		printf("Generating for %s\n", subjects[i]);
        snprintf( cafilename, sizeof(cafilename), cafilepattern, i );
        snprintf( pkfilename, sizeof(pkfilename), pkfilepattern, i );
		
		int res = createSelfSignedCA( 
			&cert, &pkey, 
			pkfilename, strlen(pkfilename),
		    cafilename, strlen(cafilename),
			subjects[i], strlen(subjects[i]),
    		ksize ,
			password, strlen(password),
			CDP, strlen(CDP)
		);
		if( 0 == res ) {
			fprintf(stderr,"!! failed to create self signed ca cert:%s pk:%s\n", 
                    cafilename, pkfilename
            );
		} else {
			printf("done.\n");
		}
        if( NULL != cert ) { X509_free(cert);     cert=NULL;}
        if( NULL != pkey ) { EVP_PKEY_free(pkey); pkey=NULL;}
    }

}//eo testHighLevelAPI

void OpenSSLCrypto_CACreation_Basic_Test( void )
{
	//TODO
}

int main (int argc, char** argv) 
{
 
   CU_pSuite pSuite = NULL;
 
   /* initialize the CUnit test registry */ 
   if (CUE_SUCCESS != CU_initialize_registry())
      return CU_get_error();
 
   /* add a suite to the registry */ 
   pSuite = CU_add_suite("Suite_1", NULL, NULL);
   if (NULL == pSuite) {
      CU_cleanup_registry();
      return CU_get_error();
   }
 
   /* add the tests to the suite */ 
   if (NULL == CU_add_test(pSuite, "Creating a few self signed CA", OpenSSLCrypto_CACreation_Basic_Test)) {
      CU_cleanup_registry();
      return CU_get_error();
   }
 
   if (NULL == CU_add_test(pSuite, "Test self signed CA creation with invalid subjects", OpenSSLCrypto_CACreation_Basic_Test)) {
      CU_cleanup_registry();
      return CU_get_error();
   }
 
   /* Run all tests using the CUnit Basic interface */ 
   CU_basic_set_mode(CU_BRM_VERBOSE);
   CU_basic_run_tests();
   CU_cleanup_registry();
   return CU_get_error();
}


