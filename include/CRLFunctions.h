/*
Functions used for the CRL file.
*/

X509_CRL *getNewCRLFromPath(std::string CRLFilePath);

std::string getRevokedSerialNumberFromX509(const X509_REVOKED *input);

void printCRLSerialNumbers(std::map<std::string, int> revokedSerialNumbers);
