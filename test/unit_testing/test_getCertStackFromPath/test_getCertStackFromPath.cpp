#include "Common.h"
#include "ChainFileFunctions.h"
using namespace std;




/*
g++ -c -o Common.o Common.cpp && \
g++ -c -o ChainFileFunctions.o ChainFileFunctions.cpp && \
g++ -c -o test_getCertStackFromPath.o test_getCertStackFromPath.cpp && \
g++ -o test_getCertStackFromPath Common.o ChainFileFunctions.o test_getCertStackFromPath.o -lcrypto -lssl && \
./test_getCertStackFromPath


*/



vector<string> actualAnswer { 
                                "3F527E677D00558272AC90D1620B67F4", 
                                "0997ED109D1F07FC", 
                                "7B2C9BD316803299"
                            };

vector<string> getVectorOfSerialNumbers(STACK_OF(X509) *certStack)
{
    vector<string> output;
    int numberOfCertificatesInChain = sk_X509_num(certStack); // Get the number of certificates in the chain file.

    for (int i = 0; i < numberOfCertificatesInChain; i++)
    {
        X509 *thisCert = sk_X509_value(certStack, i);                        // Pick one cert from the stack.
        output.push_back(getSerialNumberFromX509(thisCert)); // Add the serial number to the functionOutputSerialNumbers vector.
    }

    return output;
}

int test()
{
    string chainFilePath = "/home/pranav/Desktop/CRL-OSCP-Validator/test/test_cert _files/test1/chain.pem";

    STACK_OF(X509) * certStack = getCertStackFromPath(chainFilePath);

    vector<string> functionOutput = getVectorOfSerialNumbers(certStack);

    if(functionOutput == actualAnswer)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

int main()
{
    // This is a basic functionality test of getCertStackFromPath. 
    // This function just handles one case of all correct inputs, any erros cause exit (-1).

    cout << "\n\nUnit testing of the funciton 'test_getCertStackFromPath': "<< endl;
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