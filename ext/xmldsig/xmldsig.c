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
#include "xmldsig.h"
#include "xmldsig-internal.h"

/*
 * main module
 */
VALUE mXMLDSIG;

/*
 * OpenSSLError < StandardError
 */
VALUE eXMLDSIGError;

VALUE mSignatureAlgorithms;
VALUE mTransformAlgorithms;
VALUE mDigestAlgorithms;
VALUE mHmacAlgorithms;

ID sRSA_SHA1, sRSA_SHA256, sRSA_SHA384, sRSA_SHA512;
ID sDSA_SHA1, sDSA_SHA256;
ID sECDSA_SHA1, sECDSA_SHA256, sECDSA_SHA384, sECDSA_SHA512;

ID sC14N_10, sC14N_11, sEXC_C14N_10, sC14N_10_COMMENTS, sC14N_11_COMMENTS, sEXC_C14N_10_COMMENTS;
ID sBASE64;
ID sENVELOPED_SIGNATURE;
ID sXPATH, sXPATH_FILTER2, sXSLT;

ID sSHA1, sSHA256, sSHA384, sSHA512;

ID sHMAC_SHA1, sHMAC_SHA256, sHMAC_SHA384, sHMAC_SHA512;

ID sKEY, sCERT, sCA_CERTS, sSIGNATURE_METHOD,
   sDIGEST_METHOD, sC14N_METHOD, sREFERENCES,
   sTRANSFORMS, sALGORITHM, sSIGNATURE_VALUE,
   sKEY_VALUE, sDIGEST_VALUE, sID, sURI, sTYPE;

const unsigned char *NS_DSIG, *NS_DSIG11; 

const unsigned char *N_SIGNATURE, *N_SIGNED_INFO, *N_SIGNATURE_VALUE,
                    *N_C14N_METHOD, *N_SIGNATURE_METHOD, *N_REFERENCE,
		    *N_TRANSFORMS, *N_TRANSFORM, 
		    *N_DIGEST_METHOD, *N_DIGEST_VALUE;

const unsigned char *A_ALGORITHM, *A_ID, *A_URI, *A_TYPE;

VALUE
xml_dsig_get_encoding(xmlDocPtr doc)
{
    const char *encoding;
    rb_encoding *rb_enc;

    if (!doc->encoding) 
	encoding = "UTF-8";
    else
	encoding = (const char *)doc->encoding;

    if ((rb_enc = rb_enc_find(encoding)) == 0) 
	rb_raise(eXMLDSIGError, "Could not load encoding %s", encoding);
    return rb_enc_from_encoding(rb_enc);
}

xmldsig_sign_ctx *
xmldsig_sign_ctx_new(void) {
    xmldsig_sign_ctx *ctx;

    if (!(ctx = (xmldsig_sign_ctx *)malloc(sizeof(xmldsig_sign_ctx))))
	return NULL;

    ctx->doc = NULL;
    ctx->doc_encoding = NULL;
    ctx->ns_dsig = NULL;
    ctx->signature = NULL;
    ctx->signed_info = NULL;
    ctx->references =NULL;

    return ctx;
}

void
xmldsig_sign_ctx_free(xmldsig_sign_ctx *ctx, int with_node) {
    if (!ctx) return;

    /* free(ctx->doc_encoding); ? */
    xmlFreeNs(ctx->ns_dsig);
    xmldsig_reference_free(ctx->references, 0);
    if (with_node) xmlFreeNode(ctx->signature);
    free(ctx);
}

xmldsig_reference *
xmldsig_reference_new(void) {
    xmldsig_reference *ref;

    if (!(ref = (xmldsig_reference *)malloc(sizeof(xmldsig_reference))))
	return NULL;

    ref->node = NULL;
    ref->transforms = NULL;
    ref->prev = NULL;
    ref->next = NULL;

    return ref;
}

void
xmldsig_reference_free(xmldsig_reference *reference, int with_node) {
    if (!reference) return;

    if (reference->next) 
	xmldsig_reference_free(reference->next, with_node);

    if (with_node) xmlFreeNode(reference->node);
    
    xmldsig_transforms_free(reference->transforms, 0);

    free(reference);
}

xmldsig_transform *
xmldsig_transforms_new(void) {
    xmldsig_transform *transform;

    if (!(transform = (xmldsig_transform *)malloc(sizeof(xmldsig_transform))))
	return NULL;

    transform->node = NULL;
    transform->in_buf = NULL;
    transform->out_buf = NULL;
    transform->in_nodes = NULL;
    transform->out_nodes = NULL;
    transform->prev = NULL;
    transform->next = NULL;
    transform->transformer = NULL;

    return transform;
}
    
void
xmldsig_transforms_free(xmldsig_transform *transforms, int with_node) {
    if (!transforms) return;

    if (transforms->next)
	xmldsig_transforms_free(transforms->next, with_node);

    if (with_node) xmlFreeNode(transforms->node);

    free(transforms->in_buf);
    free(transforms->out_buf);
    xmlXPathFreeNodeSet(transforms->in_nodes);
    xmlXPathFreeNodeSet(transforms->out_nodes);

    free(transforms);
}

xmldsig_transform_result *
xmldsig_transform_result_new(void) {
    xmldsig_transform_result *result;

    if (!(result = (xmldsig_transform_result *)malloc(sizeof(xmldsig_transform_result))))
	return NULL;

    result->bytes_len = 0;
    result->bytes = NULL;
    result->nodes = NULL;

    return result;
}

void
xmldsig_transform_result_free(xmldsig_transform_result *result) {
    if (!result) return;

    free(result->bytes);
    xmlXPathFreeNodeSet(result->nodes);
    free(result);
}


void
Init_xmldsig(void)
{
    rb_encoding *utf8;

    /* sanity check */
    LIBXML_TEST_VERSION

    mXMLDSIG = rb_define_module("XmlDsig");

    /*
     * Generic error,
     * common for all classes under XmlDsig module
     */
    eXMLDSIGError = rb_define_class_under(mXMLDSIG,"XmlDsigError",rb_eStandardError);

    /*
     * Init symbols and algorithm classes
     */
    mSignatureAlgorithms = rb_define_module_under(mXMLDSIG, "SignatureAlgorithms");
    mTransformAlgorithms = rb_define_module_under(mXMLDSIG, "TransformAlgorithms");
    mDigestAlgorithms = rb_define_module_under(mXMLDSIG, "DigestAlgorithms");
    mHmacAlgorithms = rb_define_module_under(mXMLDSIG, "HmacAlgorithms");

    sRSA_SHA1 = rb_intern("RSA_SHA1");
    sRSA_SHA256 = rb_intern("RSA_SHA256");
    sRSA_SHA384 = rb_intern("RSA_SHA384");
    sRSA_SHA512 = rb_intern("RSA_SHA512");
    sDSA_SHA1 = rb_intern("DSA_SHA1");
    sDSA_SHA256 = rb_intern("DSA_SHA256");
    sECDSA_SHA1 = rb_intern("ECDSA_SHA1");
    sECDSA_SHA256 = rb_intern("ECDSA_SHA256");
    sECDSA_SHA384 = rb_intern("ECDSA_SHA384");
    sECDSA_SHA512 = rb_intern("ECDSA_SHA512");
    sC14N_10 = rb_intern("C14N_10");
    sC14N_11 = rb_intern("C14N_11");
    sEXC_C14N_10 = rb_intern("EXC_C14N_10");
    sC14N_10_COMMENTS = rb_intern("C14N_10_COMMENTS");
    sC14N_11_COMMENTS = rb_intern("C14N_11_COMMENTS");
    sEXC_C14N_10_COMMENTS = rb_intern("EXC_C14N_10_COMMENTS");
    sBASE64 = rb_intern("BASE64");
    sENVELOPED_SIGNATURE = rb_intern("ENVELOPED_SIGNATURE");
    sXPATH = rb_intern("XPATH");
    sXPATH_FILTER2 = rb_intern("XPATH_FILTER2");
    sXSLT = rb_intern("XSLT");
    sSHA1 = rb_intern("SHA1");
    sSHA256 = rb_intern("SHA256");
    sSHA384 = rb_intern("SHA384");
    sSHA512 = rb_intern("SHA512");
    sHMAC_SHA1 = rb_intern("HMAC_SHA1");
    sHMAC_SHA256 = rb_intern("HMAC_SHA256");
    sHMAC_SHA384 = rb_intern("HMAC_SHA384");
    sHMAC_SHA512 = rb_intern("HMAC_SHA512");
    
    sKEY = rb_intern("key");
    sCERT = rb_intern("cert");
    sCA_CERTS = rb_intern("ca_certs");
    sSIGNATURE_METHOD = rb_intern("signature_method");
    sC14N_METHOD = rb_intern("c14n_method");
    sDIGEST_METHOD = rb_intern("digest_method");
    sREFERENCES = rb_intern("references");
    sTRANSFORMS = rb_intern("transforms");
    sALGORITHM = rb_intern("algorithm");
    sSIGNATURE_VALUE = rb_intern("signature_value");
    sDIGEST_VALUE = rb_intern("digest_value");
    sKEY_VALUE = rb_intern("key_value");
    sID = rb_intern("id");
    sURI = rb_intern("uri");
    sTYPE = rb_intern("type");
    sENCODING = rb_intern("encoding");

    NS_DSIG = CHAR2BYTES("http://www.w3.org/2000/09/xmldsig#");
    NS_DSIG11 = CHAR2BYTES("http://www.w3.org/2000/xmldsig11#");
    NS_DSIG_PREFIX = CHAR2BYTES("dsig");
    NS_DSIG11_PREFIX = CHAR2BYTES("dsig11");

    N_SIGNATURE = CHAR2BYTES("Signature");
    N_SIGNED_INFO = CHAR2BYTES("SignedInfo");
    N_SIGNATURE_VALUE = CHAR2BYTES("SignatureValue");
    N_C14N_METHOD = CHAR2BYTES("CanonicalizationMethod");
    N_SIGNATURE_METHOD = CHAR2BYTES("SignatureMethod");
    N_REFERENCE = CHAR2BYTES("Reference");
    N_TRANSFORMS = CHAR2BYTES("Transforms");
    N_TRANSFORM = CHAR2BYTES("Tranform");
    N_DIGEST_METHOD = CHAR2BYTES("DigestMethod");
    N_DIGEST_VALUE = CHAR2BYTES("DigestValue");

    A_ALGORITHM = CHAR2BYTES("Algorithm");
    A_ID = CHAR2BYTES("Id");
    A_URI = CHAR2BYTES("URI");
    A_TYPE = CHAR2BYTES("Type");

    utf8 = rb_enc_find("UTF-8");

    rb_const_set(mSignatureAlgorithms, sRSA_SHA1, rb_enc_associate(rb_str_new2("http://www.w3.org/2000/09/xmldsig#rsa-sha1"), utf8));
    rb_const_set(mSignatureAlgorithms, sRSA_SHA256, rb_enc_associate(rb_str_new2("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"), utf8));
    rb_const_set(mSignatureAlgorithms, sRSA_SHA384, rb_enc_associate(rb_str_new2("http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"), utf8));
    rb_const_set(mSignatureAlgorithms, sRSA_SHA512, rb_enc_associate(rb_str_new2("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"), utf8));
    rb_const_set(mSignatureAlgorithms, sDSA_SHA1, rb_enc_associate(rb_str_new2("http://www.w3.org/2000/09/xmldsig#dsa-sha1"), utf8));
    rb_const_set(mSignatureAlgorithms, sDSA_SHA256, rb_enc_associate(rb_str_new2("http://www.w3.org/2009/xmldsig11#dsa-sha256"), utf8));
    rb_const_set(mSignatureAlgorithms, sECDSA_SHA1, rb_enc_associate(rb_str_new2("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1"), utf8));
    rb_const_set(mSignatureAlgorithms, sECDSA_SHA256, rb_enc_associate(rb_str_new2("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"), utf8));
    rb_const_set(mSignatureAlgorithms, sECDSA_SHA384, rb_enc_associate(rb_str_new2("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"), utf8));
    rb_const_set(mSignatureAlgorithms, sECDSA_SHA512, rb_enc_associate(rb_str_new2("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512"), utf8));

    rb_const_set(mTransformAlgorithms, sC14N_10, rb_enc_associate(rb_str_new2("http://www.w3.org/TR/2001/REC-xml-c14n-20010315"), utf8));
    rb_const_set(mTransformAlgorithms, sC14N_11, rb_enc_associate(rb_str_new2("http://www.w3.org/2006/12/xml-c14n11"), utf8));
    rb_const_set(mTransformAlgorithms, sEXC_C14N_10, rb_enc_associate(rb_str_new2("http://www.w3.org/2001/10/xml-exc-c14n"), utf8));
    rb_const_set(mTransformAlgorithms, sC14N_10_COMMENTS, rb_enc_associate(rb_str_new2("http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"), utf8));
    rb_const_set(mTransformAlgorithms, sC14N_11_COMMENTS, rb_enc_associate(rb_str_new2("http://www.w3.org/2006/12/xml-c14n11#WithComments"), utf8));
    rb_const_set(mTransformAlgorithms, sEXC_C14N_10_COMMENTS, rb_enc_associate(rb_str_new2("http://www.w3.org/2001/10/xml-exc-c14n#WithComments"), utf8));
    rb_const_set(mTransformAlgorithms, sBASE64, rb_enc_associate(rb_str_new2("http://www.w3.org/2000/09/xmldsig#base64"), utf8));
    rb_const_set(mTransformAlgorithms, sENVELOPED_SIGNATURE, rb_enc_associate(rb_str_new2("http://www.w3.org/2000/09/xmldsig#enveloped-signature"), utf8));
    rb_const_set(mTransformAlgorithms, sXPATH, rb_enc_associate(rb_str_new2("http://www.w3.org/TR/1999/REC-xpath-19991116"), utf8));
    rb_const_set(mTransformAlgorithms, sXPATH_FILTER2, rb_enc_associate(rb_str_new2("http://www.w3.org/2002/06/xmldsig-filter2"), utf8));
    rb_const_set(mTransformAlgorithms, sXSLT, rb_enc_associate(rb_str_new2("http://www.w3.org/TR/1999/REC-xslt-19991116"), utf8));

    rb_const_set(mDigestAlgorithms, sSHA1, rb_enc_associate(rb_str_new2("http://www.w3.org/2000/09/xmldsig#sha1"), utf8));
    rb_const_set(mDigestAlgorithms, sSHA256, rb_enc_associate(rb_str_new2("http://www.w3.org/2001/04/xmlenc#sha256"), utf8));
    rb_const_set(mDigestAlgorithms, sSHA384, rb_enc_associate(rb_str_new2("http://www.w3.org/2001/04/xmldsig-more#sha384"), utf8));
    rb_const_set(mDigestAlgorithms, sSHA512, rb_enc_associate(rb_str_new2("http://www.w3.org/2001/04/xmlenc#sha512"), utf8));

    rb_const_set(mHmacAlgorithms, sHMAC_SHA1, rb_enc_associate(rb_str_new2("http://www.w3.org/2000/09/xmldsig#hmac-sha1"), utf8));
    rb_const_set(mHmacAlgorithms, sHMAC_SHA256, rb_enc_associate(rb_str_new2("http://www.w3.org/2001/04/xmldsig-more#hmac-sha256"), utf8));
    rb_const_set(mHmacAlgorithms, sHMAC_SHA384, rb_enc_associate(rb_str_new2("http://www.w3.org/2001/04/xmldsig-more#hmac-sha384"), utf8));
    rb_const_set(mHmacAlgorithms, sHMAC_SHA512, rb_enc_associate(rb_str_new2("http://www.w3.org/2001/04/xmldsig-more#hmac-sha512"), utf8));

    /*
     * Init components
     */
    Init_xmldsig_document();
    Init_xmldsig_signature();
}

