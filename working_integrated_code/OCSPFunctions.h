// These are the function declarations for OCSP functionality.

std::vector<std::string> getocspURLs(X509 *inputCert);

OCSP_CERTID *getCertificateID(X509 *thisCert, X509 *issuerCert);

OCSP_REQUEST *createOCSPRequest(OCSP_CERTID *certID, std::string ocspURL);

void parseURL(char *ocspURL, char **host, char **port, char **path, int *useSSL);

OCSP_REQ_CTX *createOCSPRequestCTX(BIO *connBIO, char *path, char *host);

void getCertificateStatus(OCSP_RESPONSE *response, OCSP_CERTID *certID, int *status, int *reason, ASN1_GENERALIZEDTIME **revokedTime);
