/*
 * $Id$
 * Xml Digital Signatures for Ruby
 * Copyright (C) 2011 Martin Bosslet <Martin.Bosslet@googlemail.com>
 * All rights reserved.
 */
/*
 * This program is licenced under the same licence as Ruby.
 * (See the file 'LICENCE'.)
 */

#if !defined(_XMLDSIG_INTERNAL_H_)
#define _XMLDSIG_INTERNAL_H_

#if defined(__cplusplus)
extern "C" {
#endif

extern ID sRSA_SHA1, sRSA_SHA256, sRSA_SHA384, sRSA_SHA512;
extern ID sDSA_SHA1, sDSA_SHA256;
extern ID sECDSA_SHA1, sECDSA_SHA256, sECDSA_SHA384, sECDSA_SHA512;

extern ID sC14N_10, sC14N_11, sEXC_C14N_10, sC14N_10_COMMENTS, sC14N_11_COMMENTS, sEXC_C14N_10_COMMENTS;
extern ID sBASE64;
extern ID sENVELOPED_SIGNATURE;
extern ID sXPATH, sXPATH_FILTER2, sXSLT;

extern ID sSHA1, sSHA256, sSHA384, sSHA512;

extern ID sHMAC_SHA1, sHMAC_SHA256, sHMAC_SHA384, sHMAC_SHA512;

extern ID sKEY, sCERT, sCA_CERTS, sSIGNATURE_METHOD,
	  sDIGEST_METHOD, sC14N_METHOD, sREFERENCES,
	  sTRANSFORMS, sID, sURI, sTYPE;

#if defined(__cplusplus)
}
#endif

#endif /* _XMLDSIG_INTERNAL_H_ */ 
