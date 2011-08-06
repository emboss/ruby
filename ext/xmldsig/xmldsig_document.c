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

#define WrapXmlDoc(klass, obj, doc) do { \
    if (!(doc)) { \
	rb_raise(rb_eRuntimeError, "xmlDocPtr was not initialized"); \
    } \
    (obj) = Data_Wrap_Struct((klass), 0, xmldsig_free_doc, (doc)); \
} while (0)
#define GetXmlDoc(obj, doc) do { \
    Data_Get_Struct((obj), xmlDoc, (doc)); \
    if (!(doc)) { \
	rb_raise(rb_eRuntimeError, "xmlDocPtr could not be initialized"); \
    } \
} while (0)
#define SafeGetXmlDoc(obj, doc) do { \
    XMLDSIG_Check_Kind((obj), cDocument); \
    GetXmlDoc((obj), (doc)); \
} while (0)

#define xmldsig_params_get_key(params)			rb_hash_aref((params), ID2SYM(sKEY))
#define xmldsig_params_get_cert(params)			rb_hash_aref((params), ID2SYM(sCERT))
#define xmldsig_params_get_ca_certs(params)		rb_hash_aref((params), ID2SYM(sCA_CERTS))
#define xmldsig_params_get_signature_method(params)	rb_hash_aref((params), ID2SYM(sSIGNATURE_METHOD))
#define xmldsig_params_get_c14n_method(params)		rb_hash_aref((params), ID2SYM(sC14N_METHOD))
#define xmldsig_params_get_references(params)		rb_hash_aref((params), ID2SYM(sREFERENCES))

VALUE cDocument;

static void
xmldsig_free_doc(xmlDocPtr doc)
{
    xmlFreeDoc(doc);
}

static VALUE
xmldsig_doc_new(VALUE self, VALUE raw)
{
    xmlDocPtr doc;
    VALUE encoding;

    if (NIL_P(raw))
	rb_raise(rb_eArgError, "Input to Document must not be nil");

    StringValue(raw);
    xmlInitParser();
    /* TODO: xmlsec says
    / required for c14n! /
    ctxt->loadsubset = XML_DETECT_IDS | XML_COMPLETE_ATTRS;
    ctxt->replaceEntities = 1;
    */
    doc = xmlParseDoc((unsigned char *)RSTRING_PTR(raw));
    xmlCleanupParser();

    if (!doc) 
	rb_raise(eXMLDSIGError, "Error parsing the XML document");

    WrapXmlDoc(cDocument, self, doc);
    encoding = xml_dsig_get_encoding(doc);
    rb_ivar_set(self, sENCODING, encoding);
    return self;
}

static VALUE
xmldsig_doc_bytes(VALUE self)
{
    xmlDocPtr doc;
    unsigned char *encoded;
    int size;
    VALUE ret_val;

    GetXmlDoc(self, doc);

    xmlDocDumpMemory(doc, &encoded, &size);
    if (size <= 0)
       rb_raise(eXMLDSIGError, "Error when encoding the Document");	
    ret_val = rb_str_new2((char *)encoded);
    rb_enc_associate(ret_val, rb_to_encoding(rb_ivar_get(self, sENCODING)));

    return ret_val;
}


static VALUE
int_xmldsig_parse_signatures(VALUE self) {
    /* TODO */
    return rb_ary_new();
}

static VALUE
xmldsig_doc_signatures(VALUE self)
{
    VALUE signatures;

    signatures = rb_iv_get(self, "signatures");

    if (NIL_P(signatures)) {
	signatures = int_xmldsig_parse_signatures(self);
	rb_iv_set(self, "signatures", signatures);
    }

    return signatures;
}

static void
int_xmldsig_init_params(xmldsig_sign_params *sign_params, VALUE pkey, VALUE params)
{
    sign_params->key = pkey;
    sign_params->cert = NIL_P(params) ? Qnil : xmldsig_params_get_cert(params);
    sign_params->ca_certs = NIL_P(params) ? Qnil : xmldsig_params_get_ca_certs(params);
    sign_params->signature_method = NIL_P(params) ? Qnil : xmldsig_params_get_signature_method(params);
    sign_params->c14n_method = NIL_P(params) ? Qnil : xmldsig_params_get_c14n_method(params);
    sign_params->references = NIL_P(params) ? Qnil : xmldsig_params_get_references(params);

    /* defaults */
    if (NIL_P(sign_params->signature_method))
	sign_params->signature_method = rb_const_get(mSignatureAlgorithms, sRSA_SHA256);
    if (NIL_P(sign_params->c14n_method))
	sign_params->c14n_method = rb_const_get(mTransformAlgorithms, sC14N_10);
    if (NIL_P(sign_params->references)) {
	VALUE ref_ary, ref, transforms_ary, enveloped_sig;
       
	/* default is enveloped signature with SHA-256 */
	ref_ary = rb_ary_new();
	transforms_ary = rb_ary_new();
	enveloped_sig = rb_funcall(cTransform, rb_intern("new"), 1, ID2SYM(sENVELOPED_SIGNATURE));
	rb_ary_push(transforms_ary, enveloped_sig);
	ref = rb_funcall(cReference, rb_intern("new"), 1, transforms_ary);
	rb_ivar_set(ref, sURI, rb_str_new2(""));
	rb_ivar_set(ref, sDIGEST_METHOD, sSHA256);
	rb_ivar_set(ref, sTRANSFORMS, transforms_ary);
	rb_ary_push(ref_ary, ref);
	sign_params->references = ref_ary;
    }
}

static VALUE
xmldsig_doc_sign(int argc, VALUE *argv, VALUE self)
{
    xmlDocPtr doc;
    VALUE pkey, params, signature, signatures;
    rb_encoding *encoding;
    xmldsig_sign_params sign_params;

    rb_scan_args(argc, argv, "11", &pkey, &params);

    int_xmldsig_init_params(&sign_params, pkey, params);
    GetXmlDoc(self, doc);
    encoding = rb_to_encoding(rb_ivar_get(self, sENCODING));
    signature = xmldsig_sig_sign(doc, encoding, &sign_params);
    signatures = xmldsig_doc_signatures(self);
    rb_ary_push(signatures, signature);

    return signature;
}

void
Init_xmldsig_document(void)
{
    cDocument = rb_define_class_under(mXMLDSIG, "Document", rb_cObject);
    rb_define_singleton_method(cDocument, "new", xmldsig_doc_new, 1);

    rb_attr(cDocument, sENCODING, 1, 0, Qfalse);
    rb_define_method(cDocument, "bytes", xmldsig_doc_bytes, 0);
    rb_define_method(cDocument, "signatures", xmldsig_doc_signatures, 0);
    rb_define_method(cDocument, "sign", xmldsig_doc_sign, -1);
}
