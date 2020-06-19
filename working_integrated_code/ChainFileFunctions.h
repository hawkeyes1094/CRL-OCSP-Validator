/*
Functions used for the chain file.


*/


STACK_OF(X509) * getCertStackFromPath(std::string certStackFilepath);


std::string getSerialNumberFromX509(X509 *input);


void printCertChainSerialNumbers(std::vector<std::string> chainFileSerialNumbers);