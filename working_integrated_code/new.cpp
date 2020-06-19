#include "Common.h"
#include "OCSPFunctions.h"
#include <stdio.h>
#include <string.h>

//

int main(int argc, char const *argv[])
{

	char *filename = "ocsp_issuer.pem";
	char *issuer_name = "ocsp_root.pem";

	// File I/O BIO
	BIO *filebio = NULL;
	filebio = BIO_new(BIO_s_file());
	if (BIO_read_filename(filebio, filename) <= 0)
	{
		printf("Error opening file using BIO\n");
		exit(-1);
	}

	X509 *cert = PEM_read_bio_X509(filebio, NULL, 0, NULL);
	if (cert == NULL)
	{
		printf("Error reading into X509 structure\n");
		exit(-1);
	}

	if (BIO_read_filename(filebio, issuer_name) <= 0)
	{
		printf("Error opening issuer file using BIO\n");
		exit(-1);
	}

	X509 *issuerCert = PEM_read_bio_X509(filebio, NULL, 0, NULL);
	if (issuerCert == NULL)
	{
		printf("Error reading issuer into X509 structure\n");
		exit(-1);
	}

	std::vector<std::string> OCSPURLs = getOCSPURLs(cert);
	std::string OCSPURL = OCSPURLs.at(0);

	OCSP_CERTID *certID = getCertificateID(cert, issuerCert);

	OCSP_REQUEST *request = createOCSPRequest(certID, OCSPURL);

	// Parse the URL
	char *host = NULL, *port = NULL, *path = NULL;
	int useSSL;
	char ocsp_url[100];
	strcpy(ocsp_url, OCSPURL.c_str());
	parseURL(ocsp_url, &host, &port, &path, &useSSL);

	// Create the connection BIO
	BIO *connBIO = NULL;
	connBIO = BIO_new_connect(host);
	if (connBIO == NULL)
	{
		std::cout << "Error creating connection BIO" << std::endl;
		exit(-1);
	}
	BIO_set_conn_port(connBIO, port);

	//
	// OCSP_REQUEST_print(outbio, req, 0);
	//

	OCSP_REQ_CTX *requestCTX = createOCSPRequestCTX(connBIO, path, host);

	// Set the OCSP request
	if (OCSP_REQ_CTX_set1_req(requestCTX, request) == 0)
	{
		std::cout << "Error setting the OCSP request CTX object" << std::endl;
		exit(-1);
	}

	// Connect to the OCSP responder
	if (BIO_do_connect(connBIO) <= 0)
	{
		std::cout << "Error connecting to BIO" << std::endl;
		exit(-1);
	}

	//Request timeout handling goes here
	//

	// Execute the connection
	OCSP_RESPONSE *response = NULL;
	int rv = OCSP_sendreq_nbio(&response, requestCTX);
	if (rv == 0)
	{
		std::cout << "Error occured in sending the request" << std::endl;
		exit(-1);
	}

	//
	// OCSP_RESPONSE_print(outbio, response, 0);
	//

	// Check the status of the certificate from the response
	int status, reason;
	ASN1_GENERALIZEDTIME *revokedTime;
	getCertificateStatus(response, certID, &status, &reason, &revokedTime);

	if (status == V_OCSP_CERTSTATUS_GOOD)
	{
		std::cout << "Certificate is valid" << std::endl;
	}
	else if (status == V_OCSP_CERTSTATUS_REVOKED)
	{
		std::cout << "Certificate is revoked" << std::endl;
		//optionally, print revokation time
		std::cout << "Revokation reason reason int = " << reason << std::endl;
	}
	else if (status == V_OCSP_CERTSTATUS_UNKNOWN)
	{
		std::cout << "Certicate status unknown" << std::endl;
	}
	else
	{
		std::cout << "No idea" << std::endl;
	}
	return 0;
}