// sudo apt-get install libssl-dev
// g++ application.cpp -lcrypto


#include<bits/stdc++.h>
#include <fstream>
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

	if(temp[0] != '/')// Yes, the file has been dragged and dropped into the console. contains single quote (') at both start and end which has to be removed.
	{
		// remove the first and last chars
		temp.erase(temp.begin() + 0);
		temp.erase(temp.end() - 1);
	}
	return temp;
}



//  Find all positions of the a subString in given string
void findAllOccurances(vector<int> & vec, string data, string toSearch)
{
	// Get the first occurrence
	int pos = data.find(toSearch);
 
	// Repeat till end is reached
	while( pos != std::string::npos)
	{
		// Add position to the vector
		vec.push_back(pos);
 
		// Get the next occurrence from the current position
		pos = data.find(toSearch, pos + toSearch.size()  );
	}
}


string _asn1int(const ASN1_INTEGER *input)
{
    BIGNUM *bn = ASN1_INTEGER_to_BN(input, NULL);
	if(!bn) {
		cout<<"Error converting ASN1INT to BIGNUM"<<endl;
		exit(-1);
	}

	char *tmp = BN_bn2hex(bn);
	if(!bn) {
		cout<<"Error converting BIGNUM to char*"<<endl;
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

string getSerialNumber(X509* x509)
{
	return _asn1int(X509_get_serialNumber(x509));
}

X509_CRL *new_CRL(const char* crl_filename)
{
	BIO *bio = BIO_new_file(crl_filename, "r");
	X509_CRL *crl_file=d2i_X509_CRL_bio(bio,NULL); //if (format == FORMAT_PEM) crl=PEM_read_bio_X509_CRL(in,NULL,NULL,NULL);
	BIO_free(bio);
	return crl_file;
}

STACK_OF(X509)* getCertStackFromFile(string cert_stack_filename) {

	char file_path[cert_stack_filename.length()];
	strcpy(file_path, cert_stack_filename.c_str());

	SSL_CTX *sslctx = SSL_CTX_new(SSLv23_server_method());
	SSL_CTX_use_certificate_chain_file(sslctx, file_path);


	STACK_OF(X509) *temp_cert_stack;
	STACK_OF(X509) *cert_stack;
	X509 *leaf;
	int num;

	
	// Get the certs from sslctx into temp_stack
	if(SSL_CTX_get0_chain_certs(sslctx, &temp_cert_stack) == 0) {
		cout<<"Error in getting stack from SSL_CTX"<<endl;
		exit(-1);
	}

	// Print the number of certs in temp stack
	num = sk_X509_num(temp_cert_stack);
	// cout<<"Number of certs in temp stack = "<<num<<endl;


	// Print the leaf cert
	leaf = SSL_CTX_get0_certificate(sslctx);


	// Create a copy of the stack
	cert_stack = X509_chain_up_ref(temp_cert_stack);
	if(cert_stack == NULL) {
		cout<<"Error creating copy of stack"<<endl;
		exit(-1);
	}


	X509_up_ref(leaf);

	//Insert the leaf cert into stack
	num = sk_X509_insert(cert_stack, leaf, 0);
	// cout<<"Inserted leaf cert into stack"<<endl;
	if(num == 0) {
		cout<<"Error inserting leaf cert into stack"<<endl;
		exit(-1);
	}
	// cout<<"Number of certs in stack = "<<num<<endl;


	SSL_CTX_free(sslctx);

	return cert_stack;

}

int main()
{
	OpenSSL_add_all_algorithms();
	ERR_load_BIO_strings();



	// Display intro message.

	cout<<"\nThis is a tool to validate a given certificate chain file against a given CRL. \n\n";
	cout<<"----------------------------------\n\n";



	//get the path of the certificate chain file
	
	cout<<"Enter the full path of the certificate chain file. ";
	cout<<"Alternatively, drag and drop the file into this terminal window."<<endl;
	string certChainFilePath;
	cin>>certChainFilePath;

	certChainFilePath = checkIfFileHasBeenDraggedIn(certChainFilePath);

	vector<string> chainFileSerialNumbers;

	STACK_OF(X509) *cert_stack = getCertStackFromFile(certChainFilePath);
	int numberOfCertificates = sk_X509_num(cert_stack);
	
	for(int i =0;i < numberOfCertificates;i++) {
		X509* temp = sk_X509_value(cert_stack, i);
		chainFileSerialNumbers.push_back(getSerialNumber(temp));
	}	


	// -----------------------------------------------------------------
	// -----------------------------------------------------------------

	cout<<"\nThese are the serial numbers in the chain file:"<<endl; // Display all serial numbers in the chain file.
	for(int i = 0 ; i < numberOfCertificates ; i++)
	{
		cout<<(i+1)<<". "<<chainFileSerialNumbers[i]<<endl;
	}
	cout<<endl;


	// We now have all serial number in the string vector chainFileSerialNumbers.

	// we can now compare these againt the serial numbers in the CRL file.

	// In case the CRL is massive, it's serial numbers can be put in a hashmap for O(1) lookup.





	// Get the CRL file path from the user.

	cout<<"Enter the full path of the CRL file. ";
	cout<<"Alternatively, drag and drop the file into this terminal window."<<endl;
	string CRLFilePath;
	cin>>CRLFilePath;

	CRLFilePath = checkIfFileHasBeenDraggedIn(CRLFilePath);



	BIO *crlbio = NULL;
	crlbio = BIO_new(BIO_s_file());

	X509_CRL *CRLFileInX509  = NULL;


	// Load the CRL from file (DER format).
	if (BIO_read_filename(crlbio, CRLFilePath.c_str()) <= 0)
	    cout<<"Error loading CRL into memory."<<endl;


	// Convert to X509 format for openssl to work on.
	CRLFileInX509 = d2i_X509_CRL_bio(crlbio, NULL);


	// Get the number of revoked certificates from the CRL.
	STACK_OF(X509_REVOKED) *rev = NULL;
	rev = X509_CRL_get_REVOKED(CRLFileInX509);

	int numberOfRevokedCeritficates = sk_X509_REVOKED_num(rev);



	// Extract serial numbers of all revoked certificates.

	vector<string> revokedSerialNumbers;
	X509_REVOKED *rev_entry = NULL;

	for(int i = 0 ; i < numberOfRevokedCeritficates ; i++)
	{
		rev_entry = sk_X509_REVOKED_value(rev, i);
		const ASN1_INTEGER *temp;
		temp = (X509_REVOKED_get0_serialNumber(rev_entry));

		// temp has to converted to a string.
		revokedSerialNumbers.push_back(_asn1int(temp)); // Add it to the revokedSerialNumbers vector.
	}

	cout<<"\nThese are the serial numbers in the CRL file:"<<endl; // Display all serial numbers in the CRT file.
	for(int i = 0 ; i < numberOfRevokedCeritficates && i < 20; i++)
	{
		cout<<(i+1)<<". "<<revokedSerialNumbers[i]<<endl;
	}
	cout<<endl;



	// Now we have 2 vectors: chainFileSerialNumbers and revokedSerialNumbers.

	// Do the checking => See if there is any cert from the chain file which is listed in the CRL. If there is, the chain file is NOT VALID.

	for(int i=0;i<numberOfCertificates;i++)
	{
		string toBeChecked = chainFileSerialNumbers[i]; // This cert's serial number (from the chain file) will be checked against all the CRT serial numbers.

		for(int j=0;j<numberOfRevokedCeritficates;j++)
		{
			if(toBeChecked == revokedSerialNumbers[j])
			{
				cout<<"\n"<<toBeChecked<<" has been revoked. INVALID CHAIN. index = "<<j+1<<endl;
				cout<<"Revoked serial number at "<<j<<" = "<<revokedSerialNumbers[j]<<endl;
				exit(1);
			}
		}
	}


	// If we reach till here, none of the chain file's certs have been revoked. It is a VALID CHAIN.
	cout<<"None of the certificates in the chain have been revoked. This is a VALID CHAIN."<<endl;

	return 0;
}
