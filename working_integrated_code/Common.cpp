/* 
For common functions required in other cpp files.

We have the following functions in file:
1. std::string convertASN1ToString(const ASN1_INTEGER *input);

*/

#include "Common.h"

std::string convertASN1ToString(const ASN1_INTEGER *input) // Converts the serial number into a string.
{
	BIGNUM *tempBignum = ASN1_INTEGER_to_BN(input, NULL);
	if (!tempBignum)
	{
		std::cerr << "Error converting ASN1INT to BIGNUM" << std::endl;
		exit(-1);
	}

	char *tempHex = BN_bn2hex(tempBignum);
	if (!tempBignum)
	{
		std::cerr << "Error converting BIGNUM to char*" << std::endl;
		BN_free(tempBignum);
		exit(-1);
	}

	std::string asn1string(tempHex);

	OPENSSL_free(tempHex);
	BN_free(tempBignum);

	return asn1string;
}
