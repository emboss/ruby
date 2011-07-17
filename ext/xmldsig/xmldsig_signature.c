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

VALUE cSignature;

void
Init_xmldsig_signature(void)
{
    cSignature = rb_define_class_under(mXMLDSIG, "Signature", rb_cObject);
}
