/*
Functions used for the chain file.


*/


STACK_OF(X509) * getCertStackFromPath(std::string certStackFilepath);


std::string getSerialNumberFromX509(X509 *input);


STACK_OF(X509) * correctCertStackOrder(STACK_OF(X509) *certStack);


void printCertChainSerialNumbers(std::vector<std::string> chainFileSerialNumbers);