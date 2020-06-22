/*
This contains functions required for OCSP functionality. The functions in this file are:
1. std::vector<std::string> getocspURLs(X509 *inputCert);
2. OCSP_CERTID *getCertificateID(X509 *thisCert, X509 *issuerCert);
3. OCSP_REQUEST *createOCSPRequest(OCSP_CERTID *certID, std::string ocspURL);
4. OCSP_REQ_CTX *createOCSPRequestCTX(BIO *connBIO, char *path, char *host);
5. void getCertificateStatus(OCSP_RESPONSE *response, OCSP_CERTID *certID, int *status, int *reason, ASN1_GENERALIZEDTIME **revokedTime);


*/

#include "Common.h"
#include "OCSPFunctions.h"


// Return a vector of OCSP Responder URLs present in the certificate
std::vector<std::string> getocspURLs(X509 *inputCert)
{
	std::vector<std::string> ocspURLs; // All URLs will be inserted here and the vector will be returned.

	// Stack will contain all URLs present in AIA extension.
	// X509_get1_ocsp() is an in-built function to get the stack of URLs from the cert.
	STACK_OF(OPENSSL_STRING) *strStack = X509_get1_ocsp(inputCert);
	int stackSize = sk_OPENSSL_STRING_num(strStack);

	for (int i = 0; i < stackSize; i++)
	{
		// Constructor initialization.
		std::string thisURL(sk_OPENSSL_STRING_value(strStack, i));

		ocspURLs.push_back(thisURL);
	}

	sk_OPENSSL_STRING_free(strStack);

	return ocspURLs;
}

// Get the certificate ID required for an OCSP request.
OCSP_CERTID *getCertificateID(X509 *thisCert, X509 *issuerCert)
{
	OCSP_CERTID *certID = NULL;
	certID = OCSP_cert_to_id(EVP_sha1(), thisCert, issuerCert);
	if (certID == NULL)
	{
		std::cerr << "Error getting CERT_ID" << std::endl;
		exit(-1);
	}
}

// Create an OCSP_REQUEST structure and add the cert ID to it.
OCSP_REQUEST *createOCSPRequest(OCSP_CERTID *certID, std::string ocspURL)
{
	OCSP_REQUEST *request = NULL;
	request = OCSP_REQUEST_new();

	// Add the certificate ID to the request.
	if (OCSP_request_add0_id(request, certID) == NULL)
	{
		std::cerr << "Error adding CERT_ID to request" << std::endl;
		exit(-1);
	}

	// Add nonce
	if (OCSP_request_add1_nonce(request, NULL, 0) == 0)
	{
		std::cerr << "Error adding nonce to request" << std::endl;
		exit(-1);
	}

	return request;
}

// Create an OCSP request context CTX structure
OCSP_REQ_CTX *createOCSPRequestCTX(BIO *connBIO, char *path, char *host)
{
	OCSP_REQ_CTX *requestCTX = NULL;
	requestCTX = OCSP_sendreq_new(connBIO, path, NULL, -1);
	if (requestCTX == NULL)
	{
		std::cerr << "Error creating request CTX object" << std::endl;
		exit(-1);
	}

	if (OCSP_REQ_CTX_add1_header(requestCTX, "Host", host) == 0)
	{
		std::cerr << "Error adding header to CTX object" << std::endl;
		exit(-1);
	}

	return requestCTX;
}

// Get the status of the certificate with ID certID from the response
void getCertificateStatus(OCSP_RESPONSE *response, OCSP_CERTID *certID, int *status, int *reason, ASN1_GENERALIZEDTIME **revokedTime)
{
	OCSP_BASICRESP *basicResp = NULL;

	basicResp = OCSP_response_get1_basic(response);
	if (basicResp == NULL)
	{
		std::cerr << "Error getting BASICRESP struct from response" << std::endl;
		exit(-1);
	}
	if (OCSP_resp_find_status(basicResp, certID, status, reason, revokedTime, NULL, NULL) == 0)
	{
		std::cerr << "Cert ID could not be found in basic response" << std::endl;
		exit(-1);
	}

	OCSP_BASICRESP_free(basicResp);

	return;
}
