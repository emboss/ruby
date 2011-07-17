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

/*
 * main module
 */
VALUE mXMLDSIG;

/*
 * OpenSSLError < StandardError
 */
VALUE eXMLDSIGError;

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

void
Init_xmldsig(void)
{
    /* sanity check */
    LIBXML_TEST_VERSION

    mXMLDSIG = rb_define_module("XmlDsig");

    /*
     * Generic error,
     * common for all classes under XmlDsig module
     */
    eXMLDSIGError = rb_define_class_under(mXMLDSIG,"XmlDsigError",rb_eStandardError);

    /*
     * Init components
     */
    Init_xmldsig_document();
    Init_xmldsig_signature();
}

