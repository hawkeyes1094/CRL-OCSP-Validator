/*
This contains functions required for OCSP functionality. The functions in this file are:
1. std::vector<std::string> getOCSPURLs(X509 *inputCert);
2. OCSP_CERTID *getCertificateID(X509 *cert, X509 *issuerCert);
3. OCSP_REQUEST *createOCSPRequest(OCSP_CERTID *certID, std::string OCSPURL);
4. void parseURL(char *OCSPURL, char **host, char **port, char **path, int *useSSL);
5. OCSP_REQ_CTX *createOCSPRequestCTX(BIO *connBIO, char *path, char *host);
6. void getCertificateStatus(OCSP_RESPONSE *response, OCSP_CERTID *certID, int *status, int *reason, ASN1_GENERALIZEDTIME **revokedTime);


*/


#include "Common.h"
#include "OCSPFunctions.h"

using namespace std;


// Return a vector of OCSP Responder URLs present in the certificate
std::vector<std::string> getOCSPURLs(X509 *inputCert)
{
	std::vector<std::string> OCSPURLs; // All URLs will be inserted here and the vector will be returned.

	// Stack will contain all URLs present in AIA extension.
	// X509_get1_ocsp() is an in-built function to get the stack of URLs from the cert.
	STACK_OF(OPENSSL_STRING) *strStack = X509_get1_ocsp(inputCert);
	int stackSize = sk_OPENSSL_STRING_num(strStack);

	for (int i = 0; i < stackSize; i++)
	{
		// Constructor initialization.
		std::string currOCSPurl(sk_OPENSSL_STRING_value(strStack, i));

		OCSPURLs.push_back(currOCSPurl);
	}

	sk_OPENSSL_STRING_free(strStack);

	return OCSPURLs;
}

// Get the certificate ID required for an OCSP request
OCSP_CERTID *getCertificateID(X509 *cert, X509 *issuerCert)
{
	OCSP_CERTID *certID = NULL;
	certID = OCSP_cert_to_id(EVP_sha1(), cert, issuerCert);
	if (certID == NULL)
	{
		std::cerr << "Error getting CERT_ID" << std::endl;
		exit(-1);
	}
}

// Create an OCSP_REQUEST structure and add the cert ID to it.
OCSP_REQUEST *createOCSPRequest(OCSP_CERTID *certID, std::string OCSPURL)
{
	OCSP_REQUEST *request = NULL;
	request = OCSP_REQUEST_new();

	// Add the certificate ID to the request
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

// Parse the URL and populate the host, port & path strings
void parseURL(char *OCSPURL, char **host, char **port, char **path, int *useSSL)
{
	if (!OCSP_parse_url(OCSPURL, host, port, path, useSSL))
	{
		std::cerr << "Error in parsing URL" << std::endl;
		exit(-1);
	}
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

// Debug func : Print the OCSP request
// int OCSP_REQUEST_print(BIO *bp, OCSP_REQUEST *o, unsigned long flags)
// {
//     int i;
//     long l;
//     OCSP_CERTID *cid = NULL;
//     OCSP_ONEREQ *one = NULL;
//     OCSP_REQINFO *inf = &o->tbsRequest;
//     OCSP_SIGNATURE *sig = o->optionalSignature;

//     if (BIO_write(bp, "OCSP Request Data:\n", 19) <= 0)
//         goto err;
//     l = ASN1_INTEGER_get(inf->version);
//     if (BIO_printf(bp, "    Version: %lu (0x%lx)", l + 1, l) <= 0)
//         goto err;
//     if (inf->requestorName != NULL) {
//         if (BIO_write(bp, "\n    Requestor Name: ", 21) <= 0)
//             goto err;
//         GENERAL_NAME_print(bp, inf->requestorName);
//     }
//     if (BIO_write(bp, "\n    Requestor List:\n", 21) <= 0)
//         goto err;
//     for (i = 0; i < sk_OCSP_ONEREQ_num(inf->requestList); i++) {
//         one = sk_OCSP_ONEREQ_value(inf->requestList, i);
//         cid = one->reqCert;
//         ocsp_certid_print(bp, cid, 8);
//         if (!X509V3_extensions_print(bp,
//                                      "Request Single Extensions",
//                                      one->singleRequestExtensions, flags, 8))
//             goto err;
//     }
//     if (!X509V3_extensions_print(bp, "Request Extensions",
//                                  inf->requestExtensions, flags, 4))
//         goto err;
//     if (sig) {
//         X509_signature_print(bp, &sig->signatureAlgorithm, sig->signature);
//         for (i = 0; i < sk_X509_num(sig->certs); i++) {
//             X509_print(bp, sk_X509_value(sig->certs, i));
//             PEM_write_bio_X509(bp, sk_X509_value(sig->certs, i));
//         }
//     }
//     return 1;
//  err:
//     return 0;
// }

// // Debug func : print the OCSP response
// int OCSP_RESPONSE_print(BIO *bp, OCSP_RESPONSE *o, unsigned long flags)
// {
//     int i, ret = 0;
//     long l;
//     OCSP_CERTID *cid = NULL;
//     OCSP_BASICRESP *br = NULL;
//     OCSP_RESPID *rid = NULL;
//     OCSP_RESPDATA *rd = NULL;
//     OCSP_CERTSTATUS *cst = NULL;
//     OCSP_REVOKEDINFO *rev = NULL;
//     OCSP_SINGLERESP *single = NULL;
//     OCSP_RESPBYTES *rb = o->responseBytes;

//     if (BIO_puts(bp, "OCSP Response Data:\n") <= 0)
//         goto err;
//     l = ASN1_ENUMERATED_get(o->responseStatus);
//     if (BIO_printf(bp, "    OCSP Response Status: %s (0x%lx)\n",
//                    OCSP_response_status_str(l), l) <= 0)
//         goto err;
//     if (rb == NULL)
//         return 1;
//     if (BIO_puts(bp, "    Response Type: ") <= 0)
//         goto err;
//     if (i2a_ASN1_OBJECT(bp, rb->responseType) <= 0)
//         goto err;
//     if (OBJ_obj2nid(rb->responseType) != NID_id_pkix_OCSP_basic) {
//         BIO_puts(bp, " (unknown response type)\n");
//         return 1;
//     }

//     if ((br = OCSP_response_get1_basic(o)) == NULL)
//         goto err;
//     rd = &br->tbsResponseData;
//     l = ASN1_INTEGER_get(rd->version);
//     if (BIO_printf(bp, "\n    Version: %lu (0x%lx)\n", l + 1, l) <= 0)
//         goto err;
//     if (BIO_puts(bp, "    Responder Id: ") <= 0)
//         goto err;

//     rid = &rd->responderId;
//     switch (rid->type) {
//     case V_OCSP_RESPID_NAME:
//         X509_NAME_print_ex(bp, rid->value.byName, 0, XN_FLAG_ONELINE);
//         break;
//     case V_OCSP_RESPID_KEY:
//         i2a_ASN1_STRING(bp, rid->value.byKey, 0);
//         break;
//     }

//     if (BIO_printf(bp, "\n    Produced At: ") <= 0)
//         goto err;
//     if (!ASN1_GENERALIZEDTIME_print(bp, rd->producedAt))
//         goto err;
//     if (BIO_printf(bp, "\n    Responses:\n") <= 0)
//         goto err;
//     for (i = 0; i < sk_OCSP_SINGLERESP_num(rd->responses); i++) {
//         if (!sk_OCSP_SINGLERESP_value(rd->responses, i))
//             continue;
//         single = sk_OCSP_SINGLERESP_value(rd->responses, i);
//         cid = single->certId;
//         if (ocsp_certid_print(bp, cid, 4) <= 0)
//             goto err;
//         cst = single->certStatus;
//         if (BIO_printf(bp, "    Cert Status: %s",
//                        OCSP_cert_status_str(cst->type)) <= 0)
//             goto err;
//         if (cst->type == V_OCSP_CERTSTATUS_REVOKED) {
//             rev = cst->value.revoked;
//             if (BIO_printf(bp, "\n    Revocation Time: ") <= 0)
//                 goto err;
//             if (!ASN1_GENERALIZEDTIME_print(bp, rev->revocationTime))
//                 goto err;
//             if (rev->revocationReason) {
//                 l = ASN1_ENUMERATED_get(rev->revocationReason);
//                 if (BIO_printf(bp,
//                                "\n    Revocation Reason: %s (0x%lx)",
//                                OCSP_crl_reason_str(l), l) <= 0)
//                     goto err;
//             }
//         }
//         if (BIO_printf(bp, "\n    This Update: ") <= 0)
//             goto err;
//         if (!ASN1_GENERALIZEDTIME_print(bp, single->thisUpdate))
//             goto err;
//         if (single->nextUpdate) {
//             if (BIO_printf(bp, "\n    Next Update: ") <= 0)
//                 goto err;
//             if (!ASN1_GENERALIZEDTIME_print(bp, single->nextUpdate))
//                 goto err;
//         }
//         if (BIO_write(bp, "\n", 1) <= 0)
//             goto err;
//         if (!X509V3_extensions_print(bp,
//                                      "Response Single Extensions",
//                                      single->singleExtensions, flags, 8))
//             goto err;
//         if (BIO_write(bp, "\n", 1) <= 0)
//             goto err;
//     }
//     if (!X509V3_extensions_print(bp, "Response Extensions",
//                                  rd->responseExtensions, flags, 4))
//         goto err;
//     if (X509_signature_print(bp, &br->signatureAlgorithm, br->signature) <= 0)
//         goto err;

//     for (i = 0; i < sk_X509_num(br->certs); i++) {
//         X509_print(bp, sk_X509_value(br->certs, i));
//         PEM_write_bio_X509(bp, sk_X509_value(br->certs, i));
//     }

//     ret = 1;
//  err:
//     OCSP_BASICRESP_free(br);
//     return ret;
// }
