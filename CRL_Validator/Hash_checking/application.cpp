// sudo apt-get install libssl-dev

/*

g++ -c -o Common.o Common.cpp
g++ -c -o ChainFileFunctions.o ChainFileFunctions.cpp
g++ -c -o CRLFunctions.o CRLFunctions.cpp
g++ -c -o application.o application.cpp
g++ -o application Common.o ChainFileFunctions.o CRLFunctions.o application.o -lcrypto -lssl
./application

*/

#include "Common.h"
#include "ChainFileFunctions.h"
#include "CRLFunctions.h"

using namespace std;

string checkIfFileHasBeenDraggedIn(string inputString) // If the file has been dragged into the console, single quotes will be present at both the start and end of the string, which have to be removed.
{
	string temp = inputString;

	if (temp[0] != '/') // Yes, the file has been dragged and dropped into the console.
	{
		// Remove the first and last chars.
		temp.erase(temp.begin() + 0);
		temp.erase(temp.end() - 1);
	}
	return temp;
}

int main()
{
	OpenSSL_add_all_algorithms();
	ERR_load_BIO_strings();

	// Display intro message.

	cout << "\nThis is a tool to validate a given certificate chain file against a given CRL.\n\n";
	cout << "Built as an in-semester project by Pranav Kulkarni and Teja Juluru. Mentored by Prof Rajesh Gopakumar and HPE Technologist Vicramaraja ARV.\n\n";
	cout << "----------------------------------------------------------------\n\n";

	// Get the path of the certificate chain file

	cout << "Enter the full path of the certificate chain file. ";
	cout << "Alternatively, drag and drop the file into this terminal window." << endl;
	string certChainFilePath;
	cin >> certChainFilePath;

	certChainFilePath = checkIfFileHasBeenDraggedIn(certChainFilePath);

	vector<string> chainFileSerialNumbers;

	STACK_OF(X509) *cert_stack = getCertStackFromPath(certChainFilePath); //Get the stack of certificates from the path.
	int numberOfCertificatesInChain = sk_X509_num(cert_stack);			  // Get the number of certificates in the chain file.

	for (int i = 0; i < numberOfCertificatesInChain; i++)
	{
		X509 *temp = sk_X509_value(cert_stack, i);						 // Pick one cert from the stack.
		chainFileSerialNumbers.push_back(getSerialNumberFromX509(temp)); // Add the serial number to the chainFileSerialNumbers vector.
	}

	// We now have all chain file's serial numbers in the string vector chainFileSerialNumbers.

	// We can now compare these againt the serial numbers in the CRL file.

	// As the CRl files usually contains thousands of entries, better to put them in a map for O(1) lookup when we iterate through chainFileSerialNumbers while cheking.

	// Get the CRL file path from the user.

	cout << "\n\nEnter the full path of the CRL file. ";
	cout << "Alternatively, drag and drop the file into this terminal window." << endl;
	string CRLFilePath;
	cin >> CRLFilePath;

	CRLFilePath = checkIfFileHasBeenDraggedIn(CRLFilePath);

	X509_CRL *CRLFileInX509 = getNewCRLFromPath(CRLFilePath);

	STACK_OF(X509_REVOKED) *revokedStack = X509_CRL_get_REVOKED(CRLFileInX509); // Get the stack of revoked certificates.

	int numberOfRevokedCeritficates = sk_X509_REVOKED_num(revokedStack); // Get the number of revoked certificates from the CRL.

	// Extract serial numbers of all revoked certificates, and puts it in a map for fast access.

	map<string, int> revokedSerialNumbers;
	X509_REVOKED *revEntry = NULL;

	for (int i = 0; i < numberOfRevokedCeritficates; i++)
	{
		revEntry = sk_X509_REVOKED_value(revokedStack, i);					//Pick one from the stack.
		string thisSerialNumber = getRevokedSerialNumberFromX509(revEntry); // Extract it's serial number.

		revokedSerialNumbers[thisSerialNumber] = (i + 1); // Add its index to the revokedSerialNumbers map. (1 - indexed)
	}

	// Now we have one vector (chainFileSerialNumbers) and one map (revokedSerialNumbers), with all the required serial numbers.

	// Do the checking. That is, see if there is any cert from the chain file which is listed in the CRL. If there is, the chain file is NOT VALID.

	int validityStatus = 0; // Let 0 be non-revoked and 1 be revoked.
	vector<string> certChainRevokedCerts;

	for (int i = 0; i < chainFileSerialNumbers.size(); i++)
	{
		string toBeChecked = chainFileSerialNumbers[i];

		if (revokedSerialNumbers[toBeChecked] != 0) // If true, this cert exists in the CRL file.
		{
			validityStatus = 1;							  // Set the status as revoked.
			certChainRevokedCerts.push_back(toBeChecked); // Add it to the list of revoked certs from the input chain file.
		}
	}

	if (validityStatus == 1) // Revoked
	{
		cout << "\nChain file is INVALID because these certificates from the chain file were found to be listed in the CRL." << endl;
		for (int i = 0; i < certChainRevokedCerts.size(); i++)
		{
			string thisCert = certChainRevokedCerts[i];
			cout << (i + 1) << ". " << thisCert << " was found at index " << revokedSerialNumbers[thisCert] << "." << endl;
		}
		cout << "\n\n";
	}
	else // Non-revoked
	{
		cout << "\nChain file is VALID because none of the certificates from the chain file were found to be listed in the CRL.\n\n";
	}

	return 0;
}