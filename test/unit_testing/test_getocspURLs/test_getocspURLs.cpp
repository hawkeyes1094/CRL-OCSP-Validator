#include "Common.h"
#include "ChainFileFunctions.h"
#include "OCSPFunctions.h"
using namespace std;




/*
g++ -c -o Common.o Common.cpp && \
g++ -c -o ChainFileFunctions.o ChainFileFunctions.cpp && \
g++ -c -o OCSPFunctions.o OCSPFunctions.cpp && \
g++ -c -o test_getocspURLs.o test_getocspURLs.cpp && \
g++ -o test_getocspURLs Common.o ChainFileFunctions.o OCSPFunctions.o test_getocspURLs.o -lcrypto -lssl && \
./test_getocspURLs


*/


vector<string> actualAnswer{"http://ocsps.ssl.com"}; // URLs in the frist cert of the hardcoded path.

int test()
{
    string chainFilePath = "/home/pranav/Desktop/CRL-OSCP-Validator/test/test_cert _files/test1/chain.pem";

    STACK_OF(X509) * certStack = getCertStackFromPath(chainFilePath);


    vector<string> functionOutput = getocspURLs(sk_X509_value(certStack, 0)); // Testing on the first cert of the chain file.

    if(functionOutput == actualAnswer)
    {
        return 1;
    }
    else
    {
        return 0;
    }

    return 0;
}

int main()
{
    // This is a basic functionality test of getCertStackFromPath. 
    // This function just handles one case of all correct inputs, any erros cause exit (-1).

    cout << "\n\nUnit testing of the funciton 'getocspURLs': "<< endl;
    if (test() == 1)
    {
        cout << "TEST result of (basicFunctionalityTest) : Success" << endl;
    }
    else
    {
        cout << "TEST result of (basicFunctionalityTest) : Failed" << endl;
    }

    return 0;
}