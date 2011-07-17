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

static void
xmldsig_finalize(VALUE dummy)
{
    xmlCleanupParser();
}

void
Init_xmldsig(void)
{
    /* Init libxml */
    xmlInitParser();
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

    rb_set_end_proc(xmldsig_finalize, Qnil);
}

