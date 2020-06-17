// sudo apt-get install libssl-dev
// g++ application.cpp -lcrypto -lssl

#include <bits/stdc++.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/safestack.h>
#include <openssl/ssl.h>
#include <string.h>
using namespace std;

string checkIfFileHasBeenDraggedIn(string inputString)
{
	string temp = inputString;

	if (temp[0] != '/') // Yes, the file has been dragged and dropped into the console. contains single quote (') at both start and end which has to be removed.
	{
		// remove the first and last chars
		temp.erase(temp.begin() + 0);
		temp.erase(temp.end() - 1);
	}
	return temp;
}

string _asn1int(const ASN1_INTEGER *input) // Converts the serial number to a string
{
	BIGNUM *bn = ASN1_INTEGER_to_BN(input, NULL);
	if (!bn)
	{
		cout << "Error converting ASN1INT to BIGNUM" << endl;
		exit(-1);
	}

	char *tmp = BN_bn2hex(bn);
	if (!bn)
	{
		cout << "Error converting BIGNUM to char*" << endl;
		BN_free(bn);
		exit(-1);
	}

	string asn1string(tmp);

	//Debug
	// cout<<"Func -> ASN1ToInt, return value = "<<asn1string<<endl;

	OPENSSL_free(tmp);
	BN_free(bn);

	return asn1string;
}

string getSerialNumber(X509 *input)
{
	return _asn1int(X509_get_serialNumber(input));
}

string getRevokedCertSerialNumber(const X509_REVOKED *input)
{
	return _asn1int(X509_REVOKED_get0_serialNumber(input));
}

X509_CRL *newCRL(string CRLFileName)
{
	BIO *crlbio = NULL;
	crlbio = BIO_new(BIO_s_file());
	if (BIO_read_filename(crlbio, CRLFileName.c_str()) <= 0)
		cout << "Error loading CRL into memory." << endl;

	X509_CRL *crl = d2i_X509_CRL_bio(crlbio, NULL); //if (format == FORMAT_PEM) crl=PEM_read_bio_X509_CRL(bio,NULL,NULL,NULL);
	if (crl == NULL)
	{
		cout << "Error converting DER to X509_CRL" << endl;
		exit(-1);
	}
	BIO_free(crlbio);
	return crl;
}

STACK_OF(X509) * getCertStackFromFile(string certStackFilepath)
{

	char filePath[certStackFilepath.length() + 1];
	strcpy(filePath, certStackFilepath.c_str());

	SSL_CTX *sslCtx = SSL_CTX_new(SSLv23_server_method());
	SSL_CTX_use_certificate_chain_file(sslCtx, filePath);

	STACK_OF(X509) * tempCertStack;
	STACK_OF(X509) * certStack;
	X509 *leaf;
	int num;

	// Get the certs from sslCtx into temp_stack
	if (SSL_CTX_get0_chain_certs(sslCtx, &tempCertStack) == 0)
	{
		cout << "Error in getting stack from SSL_CTX" << endl;
		exit(-1);
	}

	// Print the leaf cert
	leaf = SSL_CTX_get0_certificate(sslCtx);

	// Create a copy of the stack
	certStack = X509_chain_up_ref(tempCertStack); // This increases the referencability of tempCertStack by 1, and assigns it to certStack. Now, even if certStack is freed, leaf will continue to function.
	if (certStack == NULL)
	{
		cout << "Error creating copy of stack" << endl;
		exit(-1);
	}

	X509_up_ref(leaf); // This increases the referencability of leaf by 1. Now, even if sslCtx is freed, leaf will continue to function.

	//Insert the leaf cert into stack
	num = sk_X509_insert(certStack, leaf, 0);
	// cout<<"Inserted leaf cert into stack"<<endl;
	if (num == 0)
	{
		cout << "Error inserting leaf cert into stack" << endl;
		exit(-1);
	}
	// cout<<"Number of certs in stack = "<<num<<endl;

	SSL_CTX_free(sslCtx);

	return certStack;
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

	STACK_OF(X509) *cert_stack = getCertStackFromFile(certChainFilePath);
	int numberOfCertificatesInChain = sk_X509_num(cert_stack); // Get the number of certificates in the chain file.

	for (int i = 0; i < numberOfCertificatesInChain; i++)
	{
		X509 *temp = sk_X509_value(cert_stack, i);
		chainFileSerialNumbers.push_back(getSerialNumber(temp)); // Add the serial number to the chainFileSerialNumbers vector.
	}

	cout << "\nThese are the serial numbers in the chain file:" << endl; // Display all serial numbers in the chain file.
	for (int i = 0; i < numberOfCertificatesInChain; i++)
	{
		cout << (i + 1) << ". " << chainFileSerialNumbers[i] << endl;
	}
	cout << endl;

	// We now have all chain file's serial numbers in the string vector chainFileSerialNumbers.

	// We can now compare these againt the serial numbers in the CRL file.

	// As the CRl files usually contains thousands of entries, better to put them in a map for O(1) lookup when we iterate through chainFileSerialNumbers while cheking.

	// Get the CRL file path from the user.

	cout << "Enter the full path of the CRL file. ";
	cout << "Alternatively, drag and drop the file into this terminal window." << endl;
	string CRLFilePath;
	cin >> CRLFilePath;

	CRLFilePath = checkIfFileHasBeenDraggedIn(CRLFilePath);

	X509_CRL *CRLFileInX509 = newCRL(CRLFilePath);

	// Get the number of revoked certificates from the CRL.
	STACK_OF(X509_REVOKED) *revokedStack = NULL;
	revokedStack = X509_CRL_get_REVOKED(CRLFileInX509);

	int numberOfRevokedCeritficates = sk_X509_REVOKED_num(revokedStack);

	// Extract serial numbers of all revoked certificates.

	map<string, int> revokedSerialNumbers;
	X509_REVOKED *revEntry = NULL;

	for (int i = 0; i < numberOfRevokedCeritficates; i++)
	{
		revEntry = sk_X509_REVOKED_value(revokedStack, i);
		string thisSerialNumber = getRevokedCertSerialNumber(revEntry);

		// Add it to the revokedSerialNumbers map.
		revokedSerialNumbers[thisSerialNumber]++;
	}

	// Display all serial numbers in the CRT file.

	cout << "\nThese are the serial numbers in the CRL file:" << endl;
	for (map<string, int>::iterator it = revokedSerialNumbers.begin(); it != revokedSerialNumbers.end(); it++)
	{
		// cout<<(i+1)<<". "<<revokedSerialNumbers[i]<<endl;
		cout << (it->first) << endl;
	}
	cout << endl;

	// Now we have one vector (chainFileSerialNumbers) and one map (revokedSerialNumbers), with all the required serial numbers.

	// Do the checking. That is, see if there is any cert from the chain file which is listed in the CRL. If there is, the chain file is NOT VALID.

	for (int i = 0; i < numberOfCertificatesInChain; i++)
	{
		string toBeChecked = chainFileSerialNumbers[i];

		if (revokedSerialNumbers[toBeChecked] != 0) // If true, this cert exists in the CRL file.
		{
			cout << "\nThe certificate " << toBeChecked << " has been revoked. This is an INVALID CHAIN." << endl;
			exit(0);
		}
	}

	// If we reach till here, none of the chain file's certs have been revoked. It is a VALID CHAIN.
	cout << "None of the certificates in the chain have been revoked. This is a VALID CHAIN." << endl;

	return 0;
}