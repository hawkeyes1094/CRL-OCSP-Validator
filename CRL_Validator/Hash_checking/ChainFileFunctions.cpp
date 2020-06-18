/*
Functions used for the chain file.


These function definations in this file:

1. STACK_OF(X509) * getCertStackFromPath (string certStackFilepath);
2. string getSerialNumberFromX509(X509 *input);

*/

#include "Common.h"
#include "ChainFileFunctions.h"
#include <string.h> // For using strcpy.

using namespace std;

STACK_OF(X509) * getCertStackFromPath(string certStackFilepath)
{

	// Convert filepath to a C-style string, this is needed for openssl.
    char filePath[certStackFilepath.length() + 1];
    strcpy(filePath, certStackFilepath.c_str());

    SSL_CTX *sslCtx = SSL_CTX_new(SSLv23_server_method());
    SSL_CTX_use_certificate_chain_file(sslCtx, filePath);

    STACK_OF(X509) * tempCertStack;
    STACK_OF(X509) * certStack;
    X509 *leaf;
    int num;

    // Get the certs from sslCtx into temp_stack
    if (SSL_CTX_get0_chain_certs(sslCtx, &tempCertStack) == 0)
    {
        cout << "Error in getting stack from SSL_CTX" << endl;
        exit(-1);
    }

    // Print the leaf cert
    leaf = SSL_CTX_get0_certificate(sslCtx);

    // Create a copy of the stack
    certStack = X509_chain_up_ref(tempCertStack); // This increases the referencability of tempCertStack by 1, and assigns it to certStack. Now, even if certStack is freed, leaf will continue to function.
    if (certStack == NULL)
    {
        cout << "Error creating copy of stack" << endl;
        exit(-1);
    }

    X509_up_ref(leaf); // This increases the referencability of leaf by 1. Now, even if sslCtx is freed, leaf will continue to function.

    //Insert the leaf cert into stack
    num = sk_X509_insert(certStack, leaf, 0);
    // cout<<"Inserted leaf cert into stack"<<endl;
    if (num == 0)
    {
        cout << "Error inserting leaf cert into stack" << endl;
        exit(-1);
    }
    // cout<<"Number of certs in stack = "<<num<<endl;

    SSL_CTX_free(sslCtx);

    return certStack;
}


string getSerialNumberFromX509(X509 *input)
{
    return convertASN1ToString(X509_get_serialNumber(input));
}