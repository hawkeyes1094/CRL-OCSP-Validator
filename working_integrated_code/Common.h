#pragma once

/*
    All standard header files required by us.
    

*/

// #include <bits/stdc++.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/safestack.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/ocsp.h>

#include <string>
#include <iostream>
#include <vector>
#include <iterator>
#include <map>

std::string convertASN1ToString(const ASN1_INTEGER *input);
