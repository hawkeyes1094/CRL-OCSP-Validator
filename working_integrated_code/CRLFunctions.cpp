/*
Functions for the CRL file.


These function definations in this file: 

1. X509_CRL *getNewCRLFromPath(string CRLFilePath);
2. string getRevokedSerialNumberFromX509(const X509_REVOKED *input);
3. void printCRLSerialNumbers(map<string, int> revokedSerialNumbers)

*/

#include "Common.h"
#include "CRLFunctions.h"


X509_CRL *getNewCRLFromPath(std::string CRLFilePath)
{

    BIO *newCRLbio = NULL;

    newCRLbio = BIO_new(BIO_s_file());

    if (BIO_read_filename(newCRLbio, CRLFilePath.c_str()) <= 0) // Load the file (from the path) into the new BIO.
    {
        std::cout << "Error loading CRL into memory." << std::endl;
    }

    // It is possible for the CRL to be encoded in DER or PEM formats.
    // We need to check which one it is.
    // We use the fact DER encoded files always begin with byte 0x30 (aka char '0' in ASCII) and PEM encoded files begin with "----".

    char *firstByte = (char *)malloc(sizeof(char)); // Because the sizeof(char) = 1 byte.
    size_t bytesRead;
    if (BIO_read_ex(newCRLbio, firstByte, 1, &bytesRead) == 0) // Reads the first byte into firstByte.
    {
        std::cerr << "Error reading the first byte from the CRL file." << std::endl;
        exit(-1);
    }

    if (BIO_seek(newCRLbio, 0) == -1) // To reset the file BIO to the beginning of the file.
    {
        std::cerr << "Error resetting the file BIO to the beginnning of the file" << std::endl;
        exit(-1);
    }

    X509_CRL *newCRL = NULL;
    if (firstByte[0] == '\x30') //It is encoded using DER.
    {
        newCRL = d2i_X509_CRL_bio(newCRLbio, NULL);

        if (newCRL == NULL)
        {
            std::cout << "Error reading the DER encoded CRL file." << std::endl;
            exit(-1);
        }
    }
    else // It is encoded using PEM.
    {
        newCRL = PEM_read_bio_X509_CRL(newCRLbio, NULL, NULL, NULL);

        if (newCRL == NULL)
        {
            std::cout << "Error reading the PEM encoded CRL file." << std::endl;
            exit(-1);
        }
    }

    BIO_free(newCRLbio);
    return newCRL;
}

std::string getRevokedSerialNumberFromX509(const X509_REVOKED *input)
{
    return convertASN1ToString(X509_REVOKED_get0_serialNumber(input));
}

void printCRLSerialNumbers(std::map<std::string, int> revokedSerialNumbers) // Display all serial numbers in the CRL file.
{
    // Display all serial numbers in the CRT file.

    std::cout << "\nThese are the serial numbers in the CRL file:" << std::endl;
    for (std::map<std::string, int>::iterator it = revokedSerialNumbers.begin(); it != revokedSerialNumbers.end(); it++)
    {
        std::cout << (it->first) << " " << (it->second) << std::endl;
    }
    std::cout << std::endl;
}
