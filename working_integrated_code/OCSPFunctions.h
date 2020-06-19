//

std::vector<std::string> getOCSPURLs(X509 *cert);

OCSP_CERTID *getCertificateID(X509 *cert, X509 *issuerCert);

OCSP_REQUEST *createOCSPRequest(OCSP_CERTID *certID, std::string OCSPURL);

void parseURL(char *OCSPURL, char **host, char **port, char **path, int *useSSL);

OCSP_REQ_CTX *createOCSPRequestCTX(BIO *connBIO, char *path, char *host);

int OCSP_REQUEST_print(BIO *bp, OCSP_REQUEST *o, unsigned long flags);

int OCSP_RESPONSE_print(BIO *bp, OCSP_RESPONSE *o, unsigned long flags);

void getCertificateStatus(OCSP_RESPONSE *response, OCSP_CERTID *certID, int *status, int *reason, ASN1_GENERALIZEDTIME **revokedTime);
