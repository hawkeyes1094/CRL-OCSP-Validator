/*
Functions for the CRL file.


These function definations in this file: 

1. X509_CRL *getNewCRLFromPath(string CRLFilePath);
2. string getRevokedSerialNumberFromX509(const X509_REVOKED *input);
3. void printCRLSerialNumbers(map<string, int> revokedSerialNumbers)

*/


#include "Common.h"
#include "CRLFunctions.h"

using namespace std;

X509_CRL *getNewCRLFromPath(string CRLFilePath)
{
    BIO *crlbio = NULL;
    crlbio = BIO_new(BIO_s_file());
    if (BIO_read_filename(crlbio, CRLFilePath.c_str()) <= 0)
        cout << "Error loading CRL into memory." << endl;

    X509_CRL *crl = d2i_X509_CRL_bio(crlbio, NULL); //if (format == FORMAT_PEM) crl=PEM_read_bio_X509_CRL(bio,NULL,NULL,NULL);
    if (crl == NULL)
    {
        cout << "Error converting DER to X509_CRL" << endl;
        exit(-1);
    }
    BIO_free(crlbio);
    return crl;
}

string getRevokedSerialNumberFromX509(const X509_REVOKED *input)
{
    return convertASN1ToString(X509_REVOKED_get0_serialNumber(input));
}

void printCRLSerialNumbers(map<string, int> revokedSerialNumbers)  // Display all serial numbers in the CRL file.
{
    // Display all serial numbers in the CRT file.

    cout << "\nThese are the serial numbers in the CRL file:" << endl;
    for (map<string, int>::iterator it = revokedSerialNumbers.begin(); it != revokedSerialNumbers.end(); it++)
    {
        cout << (it->first) << " " << it->second << endl;
    }
    cout << endl;
}