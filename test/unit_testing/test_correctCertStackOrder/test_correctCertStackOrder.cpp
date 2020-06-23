#include "Common.h"
#include "ChainFileFunctions.h"
using namespace std;




/*

g++ -c -o Common.o Common.cpp && \
g++ -c -o ChainFileFunctions.o ChainFileFunctions.cpp && \
g++ -c -o test_correctCertStackOrder.o test_correctCertStackOrder.cpp && \
g++ -o test_correctCertStackOrder Common.o ChainFileFunctions.o test_correctCertStackOrder.o -lcrypto -lssl && \
./test_correctCertStackOrder

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
        output.push_back(getSerialNumberFromX509(thisCert)); // Add the serial number to the output vector.
    }

    return output;
}

int reversedOrder()
{

    string chainFilePath = "/home/pranav/Desktop/CRL-OSCP-Validator/test/test_cert _files/test1/reversed_chain.pem";

    STACK_OF(X509) *certStack = getCertStackFromPath(chainFilePath);

    certStack = correctCertStackOrder(certStack);

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

int correctOrder()
{
    string chainFilePath = "/home/pranav/Desktop/CRL-OSCP-Validator/test/test_cert _files/test1/chain.pem";
    
    STACK_OF(X509) *certStack = getCertStackFromPath(chainFilePath);

    certStack = correctCertStackOrder(certStack);

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
    // We will be testing 2 cases:
    // 1. order is correct. that is, leaf -> intermediat(es) -> root
    // 2. order is reversed. that is, root -> intermediat(es) -> leaf
    // i=In case of jumbled we terminate the program, so we wont be testing it here.

    cout << "\n\nUnit testing of the funciton 'correctCertStackOrder': "<< endl;
    if (correctOrder() == 1)
    {
        cout << "TEST result of (correctOrderTest) : Success" << endl;
    }
    else
    {
        cout << "TEST result of (correctOrderTest) : Failed" << endl;
    }

    if (reversedOrder() == 1)
    {
        cout << "TEST result of (reversedOrderTest) : Success" << endl;
    }
    else
    {
        cout << "TEST result of (reversedOrderTest) : Failed" << endl;
    }

    return 0;
}
