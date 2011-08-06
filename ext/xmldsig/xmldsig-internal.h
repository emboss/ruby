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

#define CHAR2BYTES(s) (unsigned char *)(s)

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
   	  sTRANSFORMS, sALGORITHM, sSIGNATURE_VALUE,
   	  sKEY_VALUE, sDIGEST_VALUE, sID, sURI, sTYPE,
	  sENCODING;

/* Namespaces */
extern const unsigned char *NS_DSIG, *NS_DSIG11; 
extern const unsigned char *NS_DSIG_PREFIX, *NS_DSIG11_PREFIX;

/* Element names */
extern const unsigned char *N_SIGNATURE, *N_SIGNED_INFO, *N_SIGNATURE_VALUE,
                           *N_C14N_METHOD, *N_SIGNATURE_METHOD, *N_REFERENCE,
			   *N_TRANSFORMS, *N_TRANSFORM, *N_DIGEST_METHOD, 
			   *N_DIGEST_VALUE;

/* Attribute names */
extern const unsigned char *A_ALGORITHM, *A_ID, *A_URI, *A_TYPE;

/* User-defined signature parameters */
typedef struct sign_params_st xmldsig_sign_params;

/* References and Transforms */
typedef struct reference_st xmldsig_reference;
typedef struct transform_st xmldsig_transform;
typedef struct transform_result_st xmldsig_transform_result;
typedef struct sign_ctx_st xmldsig_sign_ctx;

struct sign_params_st {
    VALUE key;
    VALUE cert;
    VALUE ca_certs;
    VALUE signature_method;
    VALUE c14n_method;
    VALUE references;
};

typedef int(*xmldsig_transformer_cb)(xmldsig_transform *transform);

struct reference_st {
    xmlNodePtr node; /* the node representing this reference */
    xmldsig_transform *transforms; /* the transforms declared in this reference */
    xmldsig_reference *prev;
    xmldsig_reference *next;
};

struct transform_st {
    xmlNodePtr node; /* the node representing this transform */
    unsigned char *in_buf; /* set if the input to this transform is binary data */
    unsigned char *out_buf; /* set if the output of this transform is binary data */
    xmlNodeSetPtr in_nodes; /* set if the input to this transform is a node set */
    xmlNodeSetPtr out_nodes; /* set if the output to this transform is a node set */
    xmldsig_transform *prev;
    xmldsig_transform *next;
    xmldsig_transformer_cb transformer; /* callback that executes this transform */
};

struct transform_result_st {
    long          bytes_len;
    unsigned char *bytes;
    xmlNodeSetPtr nodes;
};

struct sign_ctx_st {
    xmlDocPtr doc;
    rb_encoding *doc_encoding;
    xmlNsPtr ns_dsig;
    xmlNodePtr signature;
    xmlNodePtr signed_info;
    xmldsig_reference *references;
};

xmldsig_sign_ctx *xmldsig_sign_ctx_new(void);

void xmldsig_sign_ctx_free(xmldsig_sign_ctx *ctx, int with_node);

xmldsig_reference *xmldsig_reference_new(void);
void xmldsig_reference_free(xmldsig_reference *reference, int with_node);

xmldsig_transform *xmldsig_transforms_new(void);
void xmldsig_transforms_free(xmldsig_transform *transforms, int with_node);

xmldsig_transform_result *xmldsig_transform_result_new(void);
void xmldsig_transform_result_free(xmldsig_transform_result *result);
   

/* public functions */
VALUE xmldsig_signature_init(xmlNodePtr signature);

VALUE xmldsig_sig_sign(xmlDocPtr doc, rb_encoding *encoding, xmldsig_sign_params *params);

xmldsig_transform_result *xmldsig_transforms_execute(xmldsig_transform *transforms);

#if defined(__cplusplus)
}
#endif

#endif /* _XMLDSIG_INTERNAL_H_ */ 
