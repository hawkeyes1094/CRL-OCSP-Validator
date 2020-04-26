// sudo apt-get install libssl-dev
// g++ application.cpp -lcrypto


#include<bits/stdc++.h>
#include <fstream>

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>

using namespace std;


string checkIfFileHasBeenDraggedIn (string input)
{
	string temp = input;
	if(temp[0] != '/')// yes it has been dragged and dropped. contains ' at start and end which is to be removed.
	{
		// remove the first and last chars
		temp.erase(temp.begin() + 0);
		temp.erase(temp.end() - 1);
		input = temp;
	}
	return input;
}



//  Find all positions of the a SubString in given String
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
		pos =data.find(toSearch, pos + toSearch.size());
	}
}

string _asn1int(ASN1_INTEGER *bs)
{
    static const char hexbytes[] = "0123456789ABCDEF";
    stringstream ashex;
    for(int i=0; i<bs->length; i++)
    {
        ashex << hexbytes[ (bs->data[i]&0xf0)>>4  ] ;
        ashex << hexbytes[ (bs->data[i]&0x0f)>>0  ] ;
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



	// intro message

	cout<<"\nThis is a tool to validate a given certificate chain file against a given CRL. \n\n";
	cout<<"----------------------------------\n\n";





	//get the path of the certificate chain file
	
	cout<<"Enter the full path of the certificate chain file. ";
	cout<<"Alternatively, drag and drop the file into this terminal window."<<endl;
	string certChainFilePath;
	cin>>certChainFilePath;
	// certChainFilePath = "'/home/hawkeyes/Desktop/123.pem'";
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

	// cout<<certChainFileContent<<endl;
	






	// find all occurences of -----BEGIN CERTIFICATE-----
	vector<int> allOccurencesOfBeginCert;
	findAllOccurances(allOccurencesOfBeginCert, certChainFileContent, "-----BEGIN CERTIFICATE-----");
/*
	for(int i=0;i<allOccurencesOfBeginCert.size();i++)
	{
		cout<<allOccurencesOfBeginCert[i]<<" ";
	}cout<<endl;
*/


	//separeate the certificates into individual pem files for open ssl to act on
	int numberOfCertificates = allOccurencesOfBeginCert.size();
	int startIndex, endIndex, lengthOfThisCert;

	vector<string> individualCertificates(numberOfCertificates);

	for(int i = 0 ; i < numberOfCertificates - 1 ; i++)//extract all certs except the last one
	{
		startIndex = allOccurencesOfBeginCert[i];
		endIndex = allOccurencesOfBeginCert[i+1]; // non inclusive. That is, [startIndex, endIndex)

		lengthOfThisCert = endIndex - startIndex;

		individualCertificates[i] = certChainFileContent.substr(startIndex, lengthOfThisCert);
	}

	//extract the last one too
	startIndex = allOccurencesOfBeginCert[numberOfCertificates-1];
	endIndex = certChainFileContent.length();
	lengthOfThisCert = endIndex - startIndex;

	individualCertificates[numberOfCertificates-1] = certChainFileContent.substr( startIndex, lengthOfThisCert);

/*	for(int i=0;i<allOccurencesOfBeginCert.size();i++)
	{
		cout<<"!!!"<<individualCertificates[i]<<"!!!"<<endl;
	}cout<<endl;*/


	//working till here

	vector<string> chainFileSerialNumbers;
	// now that we have all individual certs in separate strings, we convert them to x509 format and then extract the serial numbers

	for(int i = 0 ; i < numberOfCertificates ; i++)
	{
/*
		//not necessary
		string thisCertName;

		//convert i to string
		int length = snprintf( NULL, 0, "%d", i );//length of the char array
		char *str = (char*)malloc( length );
		snprintf( str, length + 1, "%d", i );

		thisCertName = string("cert") + str + ".pem";
		// cout<<thisCertName<<endl;

		ofstream thisCertStream;
		thisCertStream.open(thisCertName);
		thisCertStream << individualCertificates[i];
		thisCertStream.close();

		*/

		BIO *bio_mem = BIO_new(BIO_s_mem());
		BIO_puts(bio_mem, individualCertificates[i].c_str());
		X509 *thisCertInX509 = PEM_read_bio_X509(bio_mem, NULL, NULL, NULL);
		chainFileSerialNumbers.push_back(getSerialNumber(thisCertInX509));

	}

	cout<<"\nThese are the serial numbers in the chain file:"<<endl;
	for(int i = 0 ; i < numberOfCertificates ; i++)
	{
		cout<<i<<". "<<chainFileSerialNumbers[i]<<endl;
	}cout<<endl;

	//we now have all serial number in the string vector chainFileSerialNumbers

	//we can now compare these againt the serial numbers in the CRL file

	//the serial numbers in the CRL files can be put in a hashmap for O(1) lookup





	// get the CRL file path

	cout<<"Enter the full path of the CRL file. ";
	cout<<"Alternatively, drag and drop the file into this terminal window."<<endl;
	string CRLFilePath;
	cin>>CRLFilePath;
	// CRLFilePath = "'/home/pranav/Desktop/hpe_project/rfc5280_CRL.crl'";
	CRLFilePath = checkIfFileHasBeenDraggedIn(CRLFilePath);


	BIO *crlbio = NULL;
	X509_CRL *CRLFileInX509  = NULL;

	crlbio = BIO_new(BIO_s_file());


	//load the CRL from file (DER format)
	if (BIO_read_filename(crlbio, CRLFilePath.c_str()) <= 0)
	    cout<<"Error loading CRL into memory."<<endl;


	// convert in X509 format for OpenSSLo work on
	CRLFileInX509 = d2i_X509_CRL_bio(crlbio, NULL);


	//get number of revoked certificates from the CRL
	STACK_OF(X509_REVOKED) *rev = NULL;
	rev = X509_CRL_get_REVOKED(CRLFileInX509);

	int numberOfRevokedCeritficates = sk_X509_REVOKED_num(rev);

	// cout<<numberOfRevokedCeritficates<<endl;



	//extract serial numbers of all revoked certificates.

	vector<string> revokedSerialNumbers;
	X509_REVOKED *rev_entry = NULL;
	for(int i = 0 ; i < numberOfRevokedCeritficates ; i++)
	{
		rev_entry = sk_X509_REVOKED_value(rev, i);
		ASN1_INTEGER *temp;
		temp = const_cast<ASN1_INTEGER*>(X509_REVOKED_get0_serialNumber(rev_entry));
		// converting frm (const ASN1_INTEGER*) to (ASN1_INTEGER*) is dangerous, can cause crashes 


		revokedSerialNumbers.push_back(_asn1int(temp));
	}

	//now we have 2 vectors: chainFileSerialNumbers and revokedSerialNumbers

	cout<<"\nThese are the serial numbers in the CRL file:"<<endl;
	for(int i = 0 ; i < numberOfRevokedCeritficates ; i++)
	{
		cout<<i<<". "<<revokedSerialNumbers[i]<<endl;
	}cout<<endl;



	// do the checking

	for(int i=0;i<numberOfCertificates;i++)
	{
		string toBeChecked = individualCertificates[i];

		for(int j=0;j<numberOfRevokedCeritficates;j++)
		{
			if(toBeChecked == revokedSerialNumbers[j])
			{
				cout<<"\n"<<toBeChecked<<" has been revoked. INVALID CHAIN."<<endl;
				exit(1);
			}
		}
	}

	cout<<"None of the certificates in the chain have been revoked. This is a VALID CHAIN."<<endl;







/*	X509_CRL *crl_file = new_CRL(CRLFilePath.c_str());
	STACK_OF(X509_REVOKED) *revoked_list = crl_file->crl->revoked;
	for (int j = 0; j < sk_X509_REVOKED_num(revoked_list); j++)
    {
        X509_REVOKED *entry = sk_X509_REVOKED_value(revoked_list, j);
        cout<<entry->serialNumber<<"!!";
    }*/


	

	




	return 0;
}