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


VALUE cDocument;

static ID sENCODING, sSIGNATURES;

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

static VALUE
xmldsig_doc_sign(int argc, VALUE *argv, VALUE self)
{
    VALUE pkey, params;

    rb_scan_args(argc, argv, "11", &pkey, &params);

    /* TODO */
}

void
Init_xmldsig_document(void)
{
    sENCODING = rb_intern("@encoding");
    sSIGNATURES = rb_intern("@signatures");

    cDocument = rb_define_class_under(mXMLDSIG, "Document", rb_cObject);
    rb_define_singleton_method(cDocument, "new", xmldsig_doc_new, 1);

    rb_attr(cDocument, rb_intern("encoding"), 1, 0, Qfalse);
    rb_define_method(cDocument, "bytes", xmldsig_doc_bytes, 0);
    rb_define_method(cDocument, "signatures", xmldsig_doc_signatures, 0);
}
