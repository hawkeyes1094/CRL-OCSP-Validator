// sudo apt-get install libssl-dev
// g++ application.cpp -lcrypto


#include<bits/stdc++.h>
#include <fstream>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>

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
    static const char hexbytes[] = "0123456789ABCDEF";
    stringstream ashex;
    for(int i=0; i<input->length; i++)
    {
        ashex << hexbytes[ (input->data[i] & 0xf0) >>4  ] ;
        ashex << hexbytes[ (input->data[i] & 0x0f) >>0  ] ;
    }
    return ashex.str();
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




	// read from the pem file into a c++ string

	ifstream certChainFileStream;
	certChainFileStream.open(certChainFilePath);
	string certChainFileContent;

	if(certChainFileStream.is_open())
	{
		string temp (   (istreambuf_iterator<char>(certChainFileStream)) , istreambuf_iterator<char>()  );
		certChainFileContent = temp;
		certChainFileStream.close();
	}
	else
	{
		cout<<"Wrong path for certificate chain file."<<endl;
		exit(1);
	}

	




	// Now, the contents of the pem file are in certChainFileContent string.
	// All certificates all begin with "-----BEGIN CERTIFICATE-----"
	// And end with "-----END CERTIFICATE-----"
	// We need to extract serial numbers from all of them.



	// Find all occurences of -----BEGIN CERTIFICATE-----
	vector<int> allOccurencesOfBeginCert; //This will store start indices of all certificates.

	findAllOccurances(allOccurencesOfBeginCert, certChainFileContent, "-----BEGIN CERTIFICATE-----");


	// Separate the certificates data into individual strings for openssl to act on.
	int numberOfCertificates = allOccurencesOfBeginCert.size();
	int startIndex, endIndex, lengthOfThisCert;

	vector<string> individualCertificates(numberOfCertificates);// Will contain all the individual certificate data as separate strings.


	for(int i = 0 ; i < numberOfCertificates - 1 ; i++)//extract all certs except the last one
	{
		startIndex = allOccurencesOfBeginCert[i];
		endIndex = allOccurencesOfBeginCert[i+1]; // non inclusive. That is, [startIndex, endIndex)

		lengthOfThisCert = endIndex - startIndex;

		individualCertificates[i] = certChainFileContent.substr(startIndex, lengthOfThisCert); // Extract the individual cert which is a substring.
	}

	// Extract the last one too.
	startIndex = allOccurencesOfBeginCert[numberOfCertificates-1];
	endIndex = certChainFileContent.length();
	lengthOfThisCert = endIndex - startIndex;

	individualCertificates[numberOfCertificates-1] = certChainFileContent.substr( startIndex, lengthOfThisCert);


	// Now that we have all individual certs in separate strings, we convert them to x509 format and then extract the serial numbers using openssl.
	vector<string> chainFileSerialNumbers;
	

	for(int i = 0 ; i < numberOfCertificates ; i++)
	{
		BIO *bio_mem = BIO_new(BIO_s_mem());
		BIO_puts(bio_mem, individualCertificates[i].c_str());

		X509 *thisCertInX509 = PEM_read_bio_X509(bio_mem, NULL, NULL, NULL);
		chainFileSerialNumbers.push_back(getSerialNumber(thisCertInX509)); // Add the serial number to the chainFileSerialNumbers vector.
	}

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
	for(int i = 0 ; i < numberOfRevokedCeritficates ; i++)
	{
		cout<<(i+1)<<". "<<revokedSerialNumbers[i]<<endl;
	}
	cout<<endl;



	// Now we have 2 vectors: chainFileSerialNumbers and revokedSerialNumbers.

	// Do the checking => See if there is any cert from the chain file which is listed in the CRL. If there is, the chain file is NOT VALID.

	for(int i=0;i<numberOfCertificates;i++)
	{
		string toBeChecked = individualCertificates[i]; // This cert's serial number (from the chain file) will be checked against all the CRT serial numbers.

		for(int j=0;j<numberOfRevokedCeritficates;j++)
		{
			if(toBeChecked == revokedSerialNumbers[j])
			{
				cout<<"\n"<<toBeChecked<<" has been revoked. INVALID CHAIN."<<endl;
				exit(1);
			}
		}
	}


	// If we reach till here, none of the chain file's certs have been revoked. It is a VALID CHAIN.
	cout<<"None of the certificates in the chain have been revoked. This is a VALID CHAIN."<<endl;

	return 0;
}