/*
Functions used for the CRL file.


Function declarations in this file: 

1. X509_CRL *getNewCRLFromPath(string CRLFilePath);
2. string getRevokedSerialNumberFromX509(const X509_REVOKED *input);

*/




X509_CRL * getNewCRLFromPath(std::string CRLFilePath);



std::string getRevokedSerialNumberFromX509(const X509_REVOKED *input);