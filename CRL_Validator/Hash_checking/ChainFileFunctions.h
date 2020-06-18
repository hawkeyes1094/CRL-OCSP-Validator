/*
Functions used for the chain file.


Function declarations in this file: 

1. STACK_OF(X509) * getCertStackFromPath (string certStackFilepath);
2. string getSerialNumberFromX509(X509 *input);

*/


STACK_OF(X509) * getCertStackFromPath(std::string certStackFilepath);


std::string getSerialNumberFromX509(X509 *input);