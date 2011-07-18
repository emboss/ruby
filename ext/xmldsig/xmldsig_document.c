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
#define xmldsig_params_get_signature_algo(params)	rb_hash_aref((params), ID2SYM(sSIGNATURE_ALGO))
#define xmldsig_params_get_c14n_algo(params)		rb_hash_aref((params), ID2SYM(sC14N_ALGO))
#define xmldsig_params_get_references(params)		rb_hash_aref((params), ID2SYM(sREFERENCES))

typedef struct sign_params_st {
    VALUE key;
    VALUE cert;
    VALUE ca_certs;
    VALUE signature_algo;
    VALUE c14n_algo;
    VALUE references;
} sign_params_t;

VALUE cDocument;

static ID sENCODING, sSIGNATURES;

static ID sKEY, sCERT, sCA_CERTS, sSIGNATURE_ALGO,
	  sC14N_ALGO, sREFERENCES;

static VALUE int_parse_signatures(VALUE self);

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
int_parse_signatures(VALUE self) {
    /* TODO */
    return rb_ary_new();
}

static VALUE
xmldsig_doc_signatures(VALUE self)
{
    VALUE signatures;

    signatures = rb_ivar_get(self, sSIGNATURES);

    if (NIL_P(signatures)) {
	signatures = int_parse_signatures(self);
	rb_ivar_set(self, sSIGNATURES, signatures);
    }

    return signatures;
}

static void
int_init_params(sign_params_t *sign_params, VALUE pkey, VALUE params)
{
    sign_params->key = pkey;
    sign_params->cert = NIL_P(params) ? Qnil : xmldsig_params_get_cert(params);
    sign_params->ca_certs = NIL_P(params) ? Qnil : xmldsig_params_get_ca_certs(params);
    sign_params->signature_algo = NIL_P(params) ? Qnil : xmldsig_params_get_signature_algo(params);
    sign_params->c14n_algo = NIL_P(params) ? Qnil : xmldsig_params_get_c14n_algo(params);
    sign_params->references = NIL_P(params) ? Qnil : xmldsig_params_get_references(params);

    /* defaults */
    if (NIL_P(sign_params->signature_algo))
	sign_params->signature_algo = rb_const_get(mSignatureAlgorithms, sRSA_SHA256);
    if (NIL_P(sign_params->c14n_algo))
	sign_params->c14n_algo = rb_const_get(mTransformAlgorithms, sC14N_10);
    if (NIL_P(sign_params->references)) {
	/* TODO */
    }
}

static VALUE
int_doc_sign(xmlDocPtr doc, sign_params_t *params)
{
    /* TODO */
    return Qnil;
}

static VALUE
xmldsig_doc_sign(int argc, VALUE *argv, VALUE self)
{
    xmlDocPtr doc;
    VALUE pkey, params, signature, signatures;
    sign_params_t sign_params;

    rb_scan_args(argc, argv, "11", &pkey, &params);

    int_init_params(&sign_params, pkey, params);
    GetXmlDoc(self, doc);
    signature = int_doc_sign(doc, &sign_params);
    signatures = rb_ivar_get(self, sSIGNATURES);
    rb_ary_push(signatures, signature);

    return signature;
}

void
Init_xmldsig_document(void)
{
    sENCODING = rb_intern("@encoding");
    sSIGNATURES = rb_intern("@signatures");

    sKEY = rb_intern("key");
    sCERT = rb_intern("cert");
    sCA_CERTS = rb_intern("ca_certs");
    sSIGNATURE_ALGO = rb_intern("signature_algo");
    sC14N_ALGO = rb_intern("c14n_algo");
    sREFERENCES = rb_intern("references");

    cDocument = rb_define_class_under(mXMLDSIG, "Document", rb_cObject);
    rb_define_singleton_method(cDocument, "new", xmldsig_doc_new, 1);

    rb_attr(cDocument, rb_intern("encoding"), 1, 0, Qfalse);
    rb_define_method(cDocument, "bytes", xmldsig_doc_bytes, 0);
    rb_define_method(cDocument, "signatures", xmldsig_doc_signatures, 0);
    rb_define_method(cDocument, "sign", xmldsig_doc_sign, -1);
}
