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

/* Forward declarations */
typedef struct _sign_params_st sign_params_t;
typedef struct _transform_st transform_t;
typedef struct _transform_result_st transform_result_t;

struct _sign_params_st {
    VALUE key;
    VALUE cert;
    VALUE ca_certs;
    VALUE signature_method;
    VALUE c14n_method;
    VALUE references;
};

typedef int(*transformer_cb)(transform_t *transform);

struct _transform_st {
  xmlNodePtr here_node;  /* the node representing this transform */
  unsigned char *in_buf; /* set if the input to this transform is binary data */
  unsigned char *out_buf; /* set if the output of this transform is binary data */
  xmlNodeSetPtr in_nodes; /* set if the input to this transform is a node set */
  xmlNodeSetPtr out_nodes; /* set if the output to this transform is a node set */
  transform_t *prev;
  transform_t *next;
  transformer_cb transformer; /* callback that executes this transform */
};

struct _transform_result_st {
  long          bytes_len;
  unsigned char *bytes;
  xmlNodeSetPtr nodes;
};

VALUE xmldsig_sig_sign(xmlDocPtr doc, sign_params_t *params);

transform_t *xmldsig_transforms_new(void);
void xmldsig_transforms_free(transform_t *transforms);

transform_result_t *xmldsig_transform_result_new(void);
void xmldsig_transform_result_free(transform_result_t *result);

transform_result_t *xmldsig_transforms_execute(transform_t *transforms);

#if defined(__cplusplus)
}
#endif

#endif /* _XMLDSIG_INTERNAL_H_ */ 
