/*
Functions used for the chain file.


These function definations in this file:

1. STACK_OF(X509) * getCertStackFromPath (string certStackFilepath);
2. string getSerialNumberFromX509(X509 *input);
3. STACK_OF(X509) * correctCertStackOrder(STACK_OF(X509) *certStack);
4. void printCertChainSerialNumbers(vectot<string> chainFileSerialNumbers)

*/

#include "Common.h"
#include "ChainFileFunctions.h"
#include <string.h> // For using strcpy.

STACK_OF(X509) * getCertStackFromPath(std::string certStackFilepath)
{
    // Convert filepath to a C-style string, this is needed for openssl.
    char filePath[certStackFilepath.length() + 1];
    strcpy(filePath, certStackFilepath.c_str());

    SSL_CTX *sslCtx = SSL_CTX_new(SSLv23_server_method()); // Create a new context object.
    if (sslCtx == NULL)
    {
        std::cerr << "Failed to create SSL_CTX object." << std::endl;
        exit(-1);
    }

    if (SSL_CTX_use_certificate_chain_file(sslCtx, filePath) != 1) // Load the chain file (from the path) into the context object.
    {
        std::cerr << "Failed to load certificates into the SSL_CTX object." << std::endl;
        exit(-1);
    }

    STACK_OF(X509) *tempCertStack = NULL;
    STACK_OF(X509) *certStack = NULL;
    X509 *leafCert;

    // Get the certs from sslCtx into tempCertStack.
    if (SSL_CTX_get0_chain_certs(sslCtx, &tempCertStack) == 0)
    {
        std::cerr << "Error in getting stack from SSL_CTX" << std::endl;
        exit(-1);
    }

    leafCert = SSL_CTX_get0_certificate(sslCtx);
    if (leafCert == NULL)
    {
        std::cerr << "Failed to get the active certificate from SSL_CTX" << std::endl;
        exit(-1);
    }

    // Create a copy of the stack
    certStack = X509_chain_up_ref(tempCertStack); // This increases the referencability of tempCertStack by 1, and assigns it to certStack. Now, even if certStack is freed, leafCert will continue to function.
    if (certStack == NULL)
    {
        std::cerr << "Error creating copy of stack" << std::endl;
        exit(-1);
    }

    X509_up_ref(leafCert); // This increases the referencability of leafCert by 1. Now, even if sslCtx is freed, leafCert will continue to function.
    if (certStack == NULL)
    {
        std::cerr << "Failed to increment the reference count of the X509* vaariable." << std::endl;
        exit(-1);
    }

    //Insert the leafCert cert into stack
    if (sk_X509_insert(certStack, leafCert, 0) == 0)
    {
        std::cerr << "Error inserting leafCert into stack" << std::endl;
        exit(-1);
    }

    SSL_CTX_free(sslCtx);

    return certStack;
}

std::string getSerialNumberFromX509(X509 *input)
{
    return convertASN1ToString(X509_get_serialNumber(input));
}

/*
We implicitly assume that the user will provide certificates of either one of the two orders :
1. leaf, intermediates, root
2. root, intermediates, leaf

The correct order required for the program to work is :
leaf , intermediates, root

This function changes the order to the correct one.
*/
STACK_OF(X509) * correctCertStackOrder(STACK_OF(X509) * certStack)
{
    X509 *firstCert = sk_X509_value(certStack, 0);

    // Implicitly assumes root is at the beginning.
    if (X509_check_ca(firstCert) == 1) // Frist cert is the root or some intermediate.
    {

        // Before we reverse the order and return, we need to check if all pairs (i, i+1) follow a (Issuer, Issuee) structure.
        for (int i = 0; i < sk_X509_num(certStack) - 1; i++)
        {
            // This checks if i issues (i+1)
            int isIssued = X509_check_issued(sk_X509_value(certStack, i), sk_X509_value(certStack, i + 1));

            if (isIssued != X509_V_OK) // if this condition is true, order is jumbled and we need to exit.
            {
                std::cerr << "The order of certificates in the chain is jumbled" << std::endl;
                exit(-1);
            }
        }

        // Allocate a new stack of the same size as the original.
        int stackSize = sk_X509_num(certStack);
        STACK_OF(X509) *newCertStack = sk_X509_new_reserve(NULL, stackSize);
        if (newCertStack == NULL)
        {
            std::cerr << "Error creating new X509 stack" << std::endl;
            exit(-1);
        }

        // Insert the certs into the new stacks in the reverse order
        for (int i = stackSize - 1; i >= 0; i--)
        {
            sk_X509_push(newCertStack, sk_X509_value(certStack, i));
        }

        sk_X509_free(certStack);

        return newCertStack;
    }
    else
    {
        // Now the first cert is definitely the leaf.
        // We need to check if all pairs (i, i+1) follow a (Issuee, Issuer) structure.
        for (int i = 0; i < sk_X509_num(certStack) - 1; i++)
        {
            int isIssued = X509_check_issued(sk_X509_value(certStack, i + 1), sk_X509_value(certStack, i));
            if (isIssued != X509_V_OK)
            {
                std::cerr << "The order of certificates in the chain is jumbled" << std::endl;
                exit(-1);
            }
        }
        return certStack;
    }
}

void printCertChainSerialNumbers(std::vector<std::string> chainFileSerialNumbers) // Display all serial numbers in the chain file.
{
    std::cout << "\nThese are the serial numbers in the chain file:" << std::endl;
    for (int i = 0; i < chainFileSerialNumbers.size(); i++)
    {
        std::cout << (i + 1) << ". " << chainFileSerialNumbers[i] << std::endl;
    }
    std::cout << std::endl;
}
